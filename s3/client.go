package s3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	appconfig "github.com/marketconnect/bfe-sl/config"
)

type Client struct {
	S3Client      *s3.Client
	PresignClient *s3.PresignClient
	BucketName    string
}

type S3File struct {
	Key          string
	LastModified time.Time
}

type ListObjectsOutput struct {
	Folders []string
	Files   []S3File
}

func NewClient(appCfg *appconfig.Config) *Client {
	resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL:    appCfg.S3Endpoint,
			Source: aws.EndpointSourceCustom,
		}, nil
	})

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithEndpointResolverWithOptions(resolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(appCfg.S3AccessKeyID, appCfg.S3SecretAccessKey, "")),
		config.WithRegion(appCfg.S3Region),
	)
	if err != nil {
		log.Fatalf("failed to load S3 config: %v", err)
	}

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	return &Client{
		S3Client:      s3Client,
		PresignClient: s3.NewPresignClient(s3Client),
		BucketName:    appCfg.S3BucketName,
	}
}

func (c *Client) ListObjects(prefix string, delimiter string) (*ListObjectsOutput, error) {
	input := &s3.ListObjectsV2Input{
		Bucket: &c.BucketName,
		Prefix: &prefix,
	}
	if delimiter != "" {
		input.Delimiter = &delimiter
	}

	result, err := c.S3Client.ListObjectsV2(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	var files []S3File
	for _, item := range result.Contents {
		if *item.Key != prefix && item.LastModified != nil && item.Size != nil && *item.Size > 0 {
			files = append(files, S3File{Key: *item.Key, LastModified: *item.LastModified})
		}
	}

	var folders []string
	for _, p := range result.CommonPrefixes {
		if p.Prefix != nil {
			folders = append(folders, *p.Prefix)
		}
	}

	return &ListObjectsOutput{Folders: folders, Files: files}, nil
}

func (c *Client) ListAllObjects(prefix string) ([]string, error) {
	var files []string
	var token *string

	for {
		input := &s3.ListObjectsV2Input{
			Bucket:            &c.BucketName,
			Prefix:            &prefix,
			ContinuationToken: token,
		}

		result, err := c.S3Client.ListObjectsV2(context.TODO(), input)
		if err != nil {
			return nil, err
		}

		for _, item := range result.Contents {
			if item.Size != nil && *item.Size > 0 {
				files = append(files, *item.Key)
			}
		}

		if result.IsTruncated == nil || !*result.IsTruncated {
			break
		}
		token = result.NextContinuationToken
	}

	return files, nil
}

func (c *Client) GetObject(objectKey string) (*s3.GetObjectOutput, error) {
	return c.S3Client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &c.BucketName,
		Key:    &objectKey,
	})
}

func (c *Client) ListAllFolders() ([]string, error) {
	folderSet := make(map[string]struct{})
	var token *string

	for {
		input := &s3.ListObjectsV2Input{
			Bucket:            &c.BucketName,
			ContinuationToken: token,
		}

		result, err := c.S3Client.ListObjectsV2(context.TODO(), input)
		if err != nil {
			return nil, err
		}

		for _, item := range result.Contents {
			if strings.Contains(*item.Key, "/") {
				pathParts := strings.Split(*item.Key, "/")
				for i := 1; i < len(pathParts); i++ {
					folderSet[strings.Join(pathParts[:i], "/")+"/"] = struct{}{}
				}
			}
		}

		if result.IsTruncated == nil || !*result.IsTruncated {
			break
		}
		token = result.NextContinuationToken
	}

	folders := make([]string, 0, len(folderSet))
	for folder := range folderSet {
		folders = append(folders, folder)
	}

	return folders, nil
}

func (c *Client) GeneratePresignedURL(objectKey string, lifetime time.Duration) (string, error) {
	req, err := c.PresignClient.PresignGetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: &c.BucketName,
		Key:    &objectKey,
	}, func(opts *s3.PresignOptions) {
		opts.Expires = lifetime
	})
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

func (c *Client) GeneratePresignedUploadURL(objectKey string, lifetime time.Duration, contentType string) (string, error) {
	req, err := c.PresignClient.PresignPutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      &c.BucketName,
		Key:         &objectKey,
		ContentType: &contentType,
	}, func(opts *s3.PresignOptions) {
		opts.Expires = lifetime
	})
	if err != nil {
		return "", err
	}

	return req.URL, nil
}

func (c *Client) CreateFolder(folderKey string) error {
	if !strings.HasSuffix(folderKey, "/") {
		folderKey += "/"
	}

	_, err := c.S3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &c.BucketName,
		Key:    &folderKey,
		Body:   bytes.NewReader([]byte{}),
	})

	return err
}

func (c *Client) UploadObject(objectKey string, data io.Reader) error {
	_, err := c.S3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &c.BucketName,
		Key:    &objectKey,
		Body:   data,
	})
	return err
}

func (c *Client) DeleteObjects(keys []string) error {
	if len(keys) == 0 {
		return nil
	}

	var objectIdentifiers []types.ObjectIdentifier
	for _, key := range keys {
		objectIdentifiers = append(objectIdentifiers, types.ObjectIdentifier{Key: aws.String(key)})
	}

	// S3 DeleteObjects can handle up to 1000 keys per request.
	// For simplicity, we'll handle this in a single batch.
	// A more robust solution would chunk this for lists > 1000.
	input := &s3.DeleteObjectsInput{
		Bucket: &c.BucketName,
		Delete: &types.Delete{
			Objects: objectIdentifiers,
			Quiet:   aws.Bool(false), // We want to know about errors
		},
	}

	result, err := c.S3Client.DeleteObjects(context.TODO(), input)
	if err != nil {
		return err
	}

	if len(result.Errors) > 0 {
		var errorStrings []string
		for _, e := range result.Errors {
			errorStrings = append(errorStrings, fmt.Sprintf("key %s: %s", *e.Key, *e.Message))
		}
		return fmt.Errorf("failed to delete some objects: %s", strings.Join(errorStrings, ", "))
	}

	return nil
}

func (c *Client) CopyObject(sourceKey, destinationKey string) error {
	copySource := url.PathEscape(c.BucketName + "/" + sourceKey)
	_, err := c.S3Client.CopyObject(context.TODO(), &s3.CopyObjectInput{
		Bucket:     &c.BucketName,
		CopySource: &copySource,
		Key:        &destinationKey,
	})
	return err
}

func (c *Client) ObjectExists(key string) (bool, error) {
	_, err := c.S3Client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: &c.BucketName,
		Key:    &key,
	})
	if err != nil {
		var nfe *types.NotFound
		if errors.As(err, &nfe) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (c *Client) PrefixExists(prefix string) (bool, error) {
	result, err := c.S3Client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket:  &c.BucketName,
		Prefix:  &prefix,
		MaxKeys: aws.Int32(1),
	})
	if err != nil {
		return false, err
	}
	return len(result.Contents) > 0, nil
}

func (c *Client) ListAllKeysUnderPrefix(prefix string) ([]string, error) {
	var keys []string
	var token *string

	for {
		input := &s3.ListObjectsV2Input{
			Bucket:            &c.BucketName,
			Prefix:            &prefix,
			ContinuationToken: token,
		}

		result, err := c.S3Client.ListObjectsV2(context.TODO(), input)
		if err != nil {
			return nil, err
		}

		for _, item := range result.Contents {
			keys = append(keys, *item.Key)
		}

		if result.IsTruncated == nil || !*result.IsTruncated {
			break
		}
		token = result.NextContinuationToken
	}

	return keys, nil
}

package s3

import (
	"bytes"
	"context"
	"io"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	appconfig "github.com/marketconnect/bfe-sl/config"
)

type Client struct {
	S3Client      *s3.Client
	PresignClient *s3.PresignClient
	BucketName    string
}

type ListObjectsOutput struct {
	Folders []string
	Files   []string
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

	var files []string
	for _, item := range result.Contents {
		if *item.Key != prefix {
			files = append(files, *item.Key)
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

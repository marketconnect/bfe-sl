package email

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	appconfig "github.com/marketconnect/bfe-sl/config"
)

type Client struct {
	SESClient *sesv2.Client
	Sender    string
	LoginURL  string
}

func NewClient(appCfg *appconfig.Config) *Client {
	resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL:           appCfg.SESEndpoint,
			SigningRegion: appCfg.SESRegion,
		}, nil
	})

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithEndpointResolverWithOptions(resolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(appCfg.SESAccessKeyID, appCfg.SESSecretAccessKey, "")),
		config.WithRegion(appCfg.SESRegion),
	)
	if err != nil {
		log.Fatalf("failed to load SES config: %v", err)
	}

	sesClient := sesv2.NewFromConfig(cfg)

	return &Client{
		SESClient: sesClient,
		Sender:    appCfg.EmailFrom,
		LoginURL:  appCfg.AppLoginURL,
	}
}

func (c *Client) SendAuthDetails(ctx context.Context, recipientEmail, username, password string) error {
	subject := "Добро пожаловать в систему"
	body := fmt.Sprintf(
		"Здравствуйте!\n\nДля вас была создана учетная запись в нашей системе.\n\nДанные для входа:\nЛогин: %s\nПароль: %s\n\nВы можете войти в систему по ссылке: %s\n\nЭто письмо сгенерировано автоматически, пожалуйста, не отвечайте на него.",
		username,
		password,
		c.LoginURL,
	)

	input := &sesv2.SendEmailInput{
		FromEmailAddress: &c.Sender,
		Destination: &types.Destination{
			ToAddresses: []string{recipientEmail},
		},
		Content: &types.EmailContent{
			Simple: &types.Message{
				Subject: &types.Content{
					Data: &subject,
				},
				Body: &types.Body{
					Text: &types.Content{
						Data: &body,
					},
				},
			},
		},
	}

	_, err := c.SESClient.SendEmail(ctx, input)
	return err
}

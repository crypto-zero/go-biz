package aliyun

import (
	"context"
	"fmt"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	dysms "github.com/alibabacloud-go/dysmsapi-20170525/v3/client"
	"github.com/crypto-zero/go-biz/verification"
)

// SMS implements MobileCodeSender using Alibaba Cloud Dysms API.
type SMS struct {
	mainlandClient *dysms.Client
	template       verification.TemplateProvider[Template]
}

// Template represents an SMS template with code and sign.
type Template struct {
	TaskID       string `json:"task_id"`       // Optional: used for global SMS
	Code         string `json:"code"`          // Template code
	SignName     string `json:"sign_name"`     // Sign name
	ParamsFormat string `json:"params_format"` // JSON format string for template parameters, e.g., `{"code":"%s"}`
}

// Compile-time assertion: AliyunSMS implements MobileCodeSender.
var _ verification.MobileCodeSender = (*SMS)(nil)

// NewSMS creates a new AliyunSMS with the given Dysms client.
func NewSMS(client *dysms.Client, template verification.TemplateProvider[Template]) *SMS {
	return &SMS{
		mainlandClient: client,
		template:       template,
	}
}

// Send sends a mobile code using the appropriate template based on the MobileCode type.
func (a *SMS) Send(_ context.Context, mobileCode *verification.MobileCode) error {
	if err := mobileCode.Validate(); err != nil {
		return err
	}
	if mobileCode.CountryCode != verification.ChinaCountryCode {
		return verification.ErrUnsupportedCountryCode
	}
	template, err := a.template.GetTemplate(mobileCode.Type)
	if err != nil {
		return err
	}
	return a.sendMessage(template.SignName,
		mobileCode.Mobile,
		template.Code, mobileCode.Format(template.ParamsFormat,
			mobileCode.Code.Code))
}

// sendMessage sends an SMS message using the specified template.
func (a *SMS) sendMessage(signName, phoneNumber, templateCode, templateParam string) error {
	request := &dysms.SendSmsRequest{}
	request.SetSignName(signName)
	request.SetPhoneNumbers(phoneNumber)
	request.SetTemplateCode(templateCode)
	request.SetTemplateParam(templateParam)
	response, err := a.mainlandClient.SendSms(request)
	if err != nil {
		return fmt.Errorf("%w: %w", verification.ErrSendFailed, err)
	}
	if response.Body != nil && response.Body.Code != nil && *response.Body.Code != "OK" {
		return fmt.Errorf("%w, response: %s", verification.ErrSendFailed, response.Body.GoString())
	}
	return nil
}

// NewAliyunMainlandSMSClient creates a new Dysms client for mainland China.
func NewAliyunMainlandSMSClient(accessKeyID, accessKeySecret, regionID, endpoint string) (*dysms.Client, error) {
	config := new(openapi.Config)
	config.SetAccessKeyId(accessKeyID).
		SetAccessKeySecret(accessKeySecret).
		SetRegionId(regionID).
		SetEndpoint(endpoint)
	client, err := dysms.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("aliyun sms new client failed, err: %w", err)
	}
	return client, nil
}

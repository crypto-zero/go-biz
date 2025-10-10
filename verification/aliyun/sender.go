package aliyun

import (
	"fmt"
	"context"
	"errors"

	"github.com/crypto-zero/go-biz/verification"
	dysms "github.com/alibabacloud-go/dysmsapi-20170525/v3/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
)

var (
	ErrTemplateNotFound = errors.New("template not found")
)

type TemplateMapper map[verification.CodeType]*Template

// SMS implements MobileCodeSender using Alibaba Cloud Dysms API.
type SMS struct {
	mainlandClient *dysms.Client
	template       TemplateMapper
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
func NewSMS(client *dysms.Client, template TemplateMapper) *SMS {
	return &SMS{
		mainlandClient: client,
		template:       template,
	}
}

// Send sends a mobile code using the appropriate template based on the MobileCode type.
func (a *SMS) Send(_ context.Context, mobileCode *verification.MobileCode) error {
	if mobileCode == nil {
		return verification.ErrNilMobileCode
	}
	if mobileCode.CountryCode == "" {
		return verification.ErrMobileCodeCountryCodeIsEmpty
	}
	if mobileCode.Mobile == "" {
		return verification.ErrMobileCodeMobileIsEmpty
	}
	if mobileCode.Code.Code == "" {
		return verification.ErrMobileCodeCodeIsEmpty
	}
	if mobileCode.Type == "" {
		return verification.ErrMobileCodeTypeIsEmpty
	}
	template, err := a.getTemplateByType(mobileCode.Type)
	if err != nil {
		return err
	}
	if err = a.sendMessageWithTemplate(template.SignName,
		mobileCode.CountryCode, mobileCode.Mobile,
		template.Code, mobileCode.Format(template.ParamsFormat,
			mobileCode.Code.Code)); err != nil {
		return err
	}
	return nil
}

// getTemplateByType retrieves the template for the given code type.
func (a *SMS) getTemplateByType(typ verification.CodeType) (*Template, error) {
	t, ok := a.template[typ]
	if !ok {
		return nil, ErrTemplateNotFound
	}
	return t, nil
}

// sendMessageWithTemplate sends an SMS message using the specified template. only supports China country code.
func (a *SMS) sendMessageWithTemplate(signName, countryCode, phoneNumber, templateCode, templateParam string) error {
	if countryCode != verification.ChinaCountryCode {
		return verification.ErrUnsupportedCountryCode
	}
	request := &dysms.SendSmsRequest{}
	request.SetSignName(signName)
	request.SetPhoneNumbers(phoneNumber)
	request.SetTemplateCode(templateCode)
	request.SetTemplateParam(templateParam)
	response, err := a.mainlandClient.SendSms(request)
	if err != nil {
		return fmt.Errorf("aliyun sms send message failed, err: %w", err)
	}
	if response.Body != nil && *response.Body.Code != "OK" {
		return fmt.Errorf("aliyun sms send message failed, response body :%s", response.Body.GoString())
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

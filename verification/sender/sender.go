package sender

import (
	"fmt"
	"context"
	"errors"

	"github.com/crypto-zero/go-biz/verification"
	dysms "github.com/alibabacloud-go/dysmsapi-20170525/v3/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
)

var (
	ErrNilMobileCode                = errors.New("mobile code is nil")
	ErrMobileCodeCountryCodeIsEmpty = errors.New("mobile code country code is empty")
	ErrMobileCodeMobileIsEmpty      = errors.New("mobile code mobile is empty")
	ErrMobileCodeCodeIsEmpty        = errors.New("mobile code code is empty")
	ErrMobileCodeTypeIsEmpty        = errors.New("mobile code type is empty")
	ErrUnsupportedCountryCode       = errors.New("unsupported country code")
	ErrTemplateNotFound             = errors.New("template not found")
)

const (
	// ChinaCountryCode is the country code for China.
	ChinaCountryCode = "86"
)

// AliyunSMS implements MobileCodeSender using Alibaba Cloud Dysms API.
type AliyunSMS struct {
	mainlandClient *dysms.Client
	template       map[verification.CodeType]*Template
}

// Template represents an SMS template with code and sign.
type Template struct {
	TaskID       string // Optional: used for global SMS
	Code         string // Template code
	SignName     string // Sign name
	ParamsFormat string // JSON format string for template parameters, e.g., `{"code":"%s"}`
}

// Compile-time assertion: AliyunSMS implements MobileCodeSender.
var _ verification.MobileCodeSender = (*AliyunSMS)(nil)

// NewAliyunSMS creates a new AliyunSMS with the given Dysms client.
func NewAliyunSMS(client *dysms.Client, template map[verification.CodeType]*Template) MobileCodeSender {
	return &AliyunSMS{
		mainlandClient: client,
		template:       template,
	}
}

// Send sends a mobile code using the appropriate template based on the MobileCode type.
func (a *AliyunSMS) Send(_ context.Context, mobileCode *verification.MobileCode) error {
	if mobileCode == nil {
		return ErrNilMobileCode
	}
	if mobileCode.CountryCode == "" {
		return ErrMobileCodeCountryCodeIsEmpty
	}
	if mobileCode.Mobile == "" {
		return ErrMobileCodeMobileIsEmpty
	}
	if mobileCode.Code.Code == "" {
		return ErrMobileCodeCodeIsEmpty
	}
	if mobileCode.Type == "" {
		return ErrMobileCodeTypeIsEmpty
	}
	template, err := a.getTemplateByType(mobileCode.Type)
	if err != nil {
		return err
	}
	if err := a.sendMessageWithTemplate(template.SignName,
		mobileCode.CountryCode, mobileCode.Mobile,
		template.Code, mobileCode.Format(template.ParamsFormat, mobileCode.Code.Code)); err != nil {
		return err
	}
	return nil
}

// getTemplateByType retrieves the template for the given message type.
func (a *AliyunSMS) getTemplateByType(typ verification.CodeType) (*Template, error) {
	t, ok := a.template[typ]
	if !ok {
		return nil, ErrTemplateNotFound
	}
	return t, nil
}

// sendMessageWithTemplate sends an SMS message using the specified template. only supports China country code.
func (a *AliyunSMS) sendMessageWithTemplate(signName, countryCode, phoneNumber, templateCode, templateParam string) error {
	if countryCode != ChinaCountryCode {
		return ErrUnsupportedCountryCode
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

package verification

import (
	dysms "github.com/alibabacloud-go/dysmsapi-20170525/v3/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	"fmt"
	"context"
	"errors"
)

const (
	// ChinaCountryCode is the country code for China.
	ChinaCountryCode = "86"
)

// MessageType represents the type of message to be sent.
type MessageType string

// AliyunSMS implements MobileCodeSender using Alibaba Cloud Dysms API.
type AliyunSMS struct {
	mainlandClient *dysms.Client
	template       map[MessageType]*Template
}

// Template represents an SMS template with code and sign.
type Template struct {
	TaskID       string // Optional: used for global SMS
	Code         string // Template code
	SignName     string // Sign name
	ParamsFormat string // JSON format string for template parameters, e.g., `{"code":"%s"}`
}

// Compile-time assertion: AliyunSMS implements MobileCodeSender.
var _ MobileCodeSender = (*AliyunSMS)(nil)

// NewAliyunSMS creates a new AliyunSMS with the given Dysms client.
func NewAliyunSMS(client *dysms.Client, template map[MessageType]*Template) MobileCodeSender {
	return &AliyunSMS{
		mainlandClient: client,
		template:       template,
	}
}

// Send sends a mobile code using the appropriate template based on the MobileCode type.
func (a *AliyunSMS) Send(_ context.Context, mobileCode *MobileCode) error {
	if mobileCode == nil {
		return errors.New("mobileCode is nil")
	}
	if mobileCode.CountryCode == "" {
		return errors.New("mobile code country code is empty")
	}
	if mobileCode.Mobile == "" {
		return errors.New("mobile code mobile is empty")
	}
	if mobileCode.Code.Code == "" {
		return errors.New("mobile code code is empty")
	}
	if mobileCode.Type == "" {
		return errors.New("mobile code type is empty")
	}
	template, err := a.getTemplateByType(MessageType(mobileCode.Type))
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
func (a *AliyunSMS) getTemplateByType(typ MessageType) (*Template, error) {
	t, ok := a.template[typ]
	if !ok {
		return nil, fmt.Errorf("template for type %s not found", typ)
	}
	return t, nil
}

// sendMessageWithTemplate sends an SMS message using the specified template. only supports China country code.
func (a *AliyunSMS) sendMessageWithTemplate(signName, countryCode, phoneNumber, templateCode, templateParam string) error {
	if countryCode != ChinaCountryCode {
		return fmt.Errorf("only support country code %s", ChinaCountryCode)
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

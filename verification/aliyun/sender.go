package aliyun

import (
	"context"
	"fmt"
	"strings"
	"text/template"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	dysms "github.com/alibabacloud-go/dysmsapi-20170525/v3/client"
	"github.com/crypto-zero/go-biz/verification"
)

// SMS implements CodeSender[MobileCode] using Alibaba Cloud Dysms API.
type SMS struct {
	mainlandClient *dysms.Client
	template       verification.TemplateProvider[verification.SMSTemplate]
}

// Compile-time assertion: SMS implements CodeSender[MobileCode].
var _ verification.CodeSender[verification.MobileCode] = (*SMS)(nil)

// NewSMS creates a new SMS with the given Dysms client.
func NewSMS(client *dysms.Client, template verification.TemplateProvider[verification.SMSTemplate]) *SMS {
	return &SMS{
		mainlandClient: client,
		template:       template,
	}
}

// Send sends a mobile code using the appropriate template based on the MobileCode type.
func (a *SMS) Send(_ context.Context, mobileCode *verification.MobileCode) error {
	if mobileCode.CountryCode != verification.ChinaCountryCode {
		return verification.ErrUnsupportedCountryCode
	}
	tmpl, err := a.template.GetTemplate(mobileCode.Type)
	if err != nil {
		return err
	}

	t, err := template.New("sms").Parse(tmpl.ParamsFormat)
	if err != nil {
		return fmt.Errorf("failed to parse sms template: %w", err)
	}

	var buf strings.Builder
	if err = t.Execute(&buf, mobileCode); err != nil {
		return fmt.Errorf("failed to execute sms template: %w", err)
	}

	return a.sendMessage(tmpl.SignName, mobileCode.Mobile, tmpl.Code, buf.String())
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

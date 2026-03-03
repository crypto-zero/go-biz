package aliyun

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"text/template"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	dysms "github.com/alibabacloud-go/dysmsapi-20170525/v3/client"
	"github.com/crypto-zero/go-biz/verification"
)

// SMS implements CodeSender[MobileCode] using Alibaba Cloud Dysms API.
type SMS struct {
	mainlandClient *dysms.Client
	provider       verification.TemplateProvider[verification.SMSTemplate]
	tmplCache      sync.Map // map[CodeType]*cachedSMSTemplate
}

// cachedSMSTemplate holds a pre-parsed SMS template alongside its metadata.
type cachedSMSTemplate struct {
	tmpl         *template.Template
	signName     string
	templateCode string // Alibaba Cloud SMS template ID, e.g. "SMS_123456"
}

// Compile-time assertion: SMS implements CodeSender[MobileCode].
var _ verification.CodeSender[verification.MobileCode] = (*SMS)(nil)

// NewSMS creates a new SMS with the given Dysms client.
func NewSMS(client *dysms.Client, provider verification.TemplateProvider[verification.SMSTemplate]) *SMS {
	return &SMS{
		mainlandClient: client,
		provider:       provider,
	}
}

// Send sends a mobile code using the appropriate template based on the MobileCode type.
//
// Note: The Alibaba Cloud Dysms SDK (v3) does not accept context.Context in
// SendSms. Consider upgrading to SendSmsWithOptions + RuntimeOptions for
// timeout control when the SDK supports it.
func (a *SMS) Send(_ context.Context, mobileCode *verification.MobileCode) error {
	if mobileCode.CountryCode != verification.ChinaCountryCode {
		return verification.ErrUnsupportedCountryCode
	}
	ct, err := a.getTemplate(mobileCode.Type)
	if err != nil {
		return err
	}

	var buf strings.Builder
	if err = ct.tmpl.Execute(&buf, mobileCode); err != nil {
		return fmt.Errorf("failed to execute sms template: %w", err)
	}

	return a.sendMessage(ct.signName, mobileCode.GetValue(), ct.templateCode, buf.String())
}

// getTemplate returns a cached, pre-parsed template for the given code type.
func (a *SMS) getTemplate(typ verification.CodeType) (*cachedSMSTemplate, error) {
	if cached, ok := a.tmplCache.Load(typ); ok {
		return cached.(*cachedSMSTemplate), nil
	}
	tmpl, err := a.provider.GetTemplate(typ)
	if err != nil {
		return nil, err
	}
	t, err := template.New("sms").Parse(tmpl.ParamsFormat)
	if err != nil {
		return nil, fmt.Errorf("failed to parse sms template: %w", err)
	}
	ct := &cachedSMSTemplate{tmpl: t, signName: tmpl.SignName, templateCode: tmpl.Code}
	a.tmplCache.Store(typ, ct)
	return ct, nil
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

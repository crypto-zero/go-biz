package verification

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	dysms "github.com/alibabacloud-go/dysmsapi-20170525/v3/client"
	"github.com/alibabacloud-go/tea/tea"
)

// ============================================================================
// SMS Sender (Aliyun Dysms)
// ============================================================================

// AliyunSMSSender implements MobileCodeSender using Alibaba Cloud Dysms API.
type AliyunSMSSender struct {
	accessKeyID     string
	accessKeySecret string
	regionID        string
	signName        string
	templateCode    string
}

// Compile-time assertion: AliyunSMSSender implements MobileCodeSender.
var _ MobileCodeSender = (*AliyunSMSSender)(nil)

// newClient builds a Dysms client with the configured credentials.
func (a *AliyunSMSSender) newClient() (*dysms.Client, error) {
	cfg := &openapi.Config{
		AccessKeyId:     tea.String(a.accessKeyID),
		AccessKeySecret: tea.String(a.accessKeySecret),
		RegionId:        tea.String(a.regionID),
	}
	cfg.Endpoint = tea.String("dysmsapi.aliyuncs.com")
	return dysms.NewClient(cfg)
}

func (a *AliyunSMSSender) formatAliyunPhone(mobile, countryCode string) string {
	cc := strings.TrimSpace(countryCode)
	m := strings.TrimSpace(mobile)
	if cc == "" || cc == "86" {
		return m // Mainland China numbers can be used directly
	}
	return cc + m
}

// Send sends the SMS using Alibaba Cloud Dysms SendSms API.
func (a *AliyunSMSSender) Send(ctx context.Context, mc *MobileCode) error {
	client, err := a.newClient()
	if err != nil {
		return fmt.Errorf("aliyun sms: create client: %w", err)
	}

	// Build template params.
	payload := map[string]string{
		"code": mc.Code.Code,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("aliyun sms: marshal template params: %w", err)
	}

	req := &dysms.SendSmsRequest{
		PhoneNumbers:  tea.String(a.formatAliyunPhone(mc.Mobile, mc.CountryCode)),
		SignName:      tea.String(a.signName),
		TemplateCode:  tea.String(a.templateCode),
		TemplateParam: tea.String(string(b)),
		OutId:         tea.String(mc.Sequence), // helpful for tracing/idempotency on our side
	}

	resp, err := client.SendSms(req)
	if err != nil {
		return fmt.Errorf("aliyun sms: send failed: %w", err)
	}

	if code := tea.StringValue(resp.Body.Code); strings.ToUpper(code) != "ok" {
		return fmt.Errorf(
			"aliyun sms send failed with code: %s, msg: %s, request_id: %s, biz_id: %s",
			tea.StringValue(resp.Body.Code),
			tea.StringValue(resp.Body.Message),
			tea.StringValue(resp.Body.RequestId),
			tea.StringValue(resp.Body.BizId),
		)
	}
	return nil
}

func NewAliyunSMSSender(ak, sk, regionID, signName, templateCode string) *AliyunSMSSender {
	return &AliyunSMSSender{
		accessKeyID:     ak,
		accessKeySecret: sk,
		regionID:        regionID,
		signName:        signName,
		templateCode:    templateCode,
	}
}

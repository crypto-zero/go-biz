package aliyun

import (
	"context"
	"errors"
	"log"
	"os"
	"testing"
	"time"

	"github.com/crypto-zero/go-biz/verification"
	"github.com/stretchr/testify/assert"
)

func mustEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", errors.New("missing env: " + key)
	}
	return v, nil
}

var (
	ak       string
	sk       string
	region   string
	endpoint string
	signCN   string
	tplCN    string
	phoneCN  string
)

func init() {
	var err error
	ak, err = mustEnv("ALIYUN_AK")
	if err != nil {
		log.Fatal(err)
		return
	}
	sk, err = mustEnv("ALIYUN_SK")
	if err != nil {
		log.Fatal(err)
		return
	}
	region, err = mustEnv("ALIYUN_REGION_ID")
	if err != nil {
		log.Fatal(err)
		return
	}
	endpoint, err = mustEnv("ALIYUN_ENDPOINT")
	if err != nil {
		log.Fatal(err)
		return
	}
	signCN, err = mustEnv("SIGN_NAME_CN")
	if err != nil {
		log.Fatal(err)
		return
	}
	tplCN, err = mustEnv("TEMPLATE_CODE_CN")
	if err != nil {
		log.Fatal(err)
		return
	}
	phoneCN, err = mustEnv("PHONE_CN")
	if err != nil {
		log.Fatal(err)
		return
	}
}

// testTemplateProvider is a test helper that implements verification.TemplateProvider.
type testTemplateProvider map[verification.CodeType]*Template

func (p testTemplateProvider) GetTemplate(typ verification.CodeType) (*Template, error) {
	t, ok := p[typ]
	if !ok {
		return nil, ErrTemplateNotFound
	}
	return t, nil
}

func TestAliyunSMS_SendMessageWithTemplate_CN(t *testing.T) {
	cli, err := NewAliyunMainlandSMSClient(ak, sk, region, endpoint)
	assert.Nil(t, err)
	sender := NewSMS(cli, testTemplateProvider{
		"LOGIN": {
			SignName:     signCN,
			Code:         tplCN,
			ParamsFormat: `{"code":"%s"}`,
		},
	})
	mobileCode, err := verification.DefaultCodeGenerator.NewMobileCode(context.TODO(), "LOGIN", 0, phoneCN, verification.ChinaCountryCode)
	assert.Nil(t, err)
	err = sender.Send(nil, mobileCode)
	assert.Nil(t, err)
	time.Sleep(2 * time.Second)
}

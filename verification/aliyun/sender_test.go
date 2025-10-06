package aliyun

import (
	"os"
	"testing"
	"time"
	"errors"
	"log"
	"github.com/stretchr/testify/assert"
	"context"
	"github.com/crypto-zero/go-biz/verification"
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

func TestAliyunSMS_SendMessageWithTemplate_CN(t *testing.T) {
	cli, err := NewAliyunMainlandSMSClient(ak, sk, region, endpoint)
	assert.Nil(t, err)
	sender := NewSMS(cli, map[verification.CodeType]*Template{
		"LOGIN": {
			SignName:     signCN,
			Code:         tplCN,
			ParamsFormat: `{"code":"%s"}`,
		},
	})
	mobileCode, err := verification.DefaultCodeGenerator.NewMobileCode(context.TODO(), "LOGIN", 0, phoneCN, verification.)
	assert.Nil(t, err)
	err = sender.Send(nil, mobileCode)
	assert.Nil(t, err)
	time.Sleep(2 * time.Second)
}

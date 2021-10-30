package v4

import (
	"github.com/golang/protobuf/proto"
	"github.com/v2fly/v2ray-core/v4/infra/conf/cfgcommon"
	"github.com/v2fly/v2ray-core/v4/proxy/ssh"
)

type SSHClientConfig struct {
	Address    *cfgcommon.Address `json:"address"`
	Port       uint32             `json:"port"`
	User       string             `json:"user"`
	Password   string             `json:"password"`
	PrivateKey string             `json:"privateKey"`
	PublicKey  string             `json:"publicKey"`
	UserLevel  uint32             `json:"userLevel"`
}

func (v *SSHClientConfig) Build() (proto.Message, error) {
	return &ssh.Config{
		Address:    v.Address.Build(),
		Port:       v.Port,
		User:       v.User,
		Password:   v.Password,
		PrivateKey: v.PrivateKey,
		PublicKey:  v.PublicKey,
		UserLevel:  v.UserLevel,
	}, nil
}

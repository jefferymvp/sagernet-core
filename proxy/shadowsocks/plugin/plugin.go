package plugin

import (
	"strings"

	"github.com/v2fly/v2ray-core/v4/proxy/shadowsocks"
	"github.com/v2fly/v2ray-core/v4/proxy/shadowsocks/plugin/external"
	"github.com/v2fly/v2ray-core/v4/proxy/shadowsocks/plugin/self"
	"github.com/v2fly/v2ray-core/v4/proxy/shadowsocks/plugin/simpleobfs"
)

func init() {
	shadowsocks.PluginCreator = func(plugin string) shadowsocks.SIP003Plugin {
		if plugin == "v2ray" || plugin == "v2ray-plugin" {
			return &self.Plugin{}
		}
		switch strings.ToLower(plugin) {
		case "v2ray", "v2ray-plugin":
			return &self.Plugin{}
		case "obfs-local":
			return &simpleobfs.Plugin{Server: false}
		case "obfs-server":
			return &simpleobfs.Plugin{Server: true}
		}

		return &external.Plugin{Plugin: plugin}
	}
}

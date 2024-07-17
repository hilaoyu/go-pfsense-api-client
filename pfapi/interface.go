package pfapi

import (
	"context"
	"encoding/json"
)

const (
	interfaceEndpoint      = "api/v1/interface"
	interfaceVLANEndpoint  = "api/v1/interface/vlan"
	interfaceApplyEndpoint = "api/v1/interface/apply"
)

// InterfaceService provides interface API methods
type InterfaceService service

type Interface struct {
	Enable                          string `json:"enable"`
	If                              string `json:"if"`
	Descr                           string `json:"descr"`
	AliasAddress                    string `json:"alias-address"`
	AliasSubnet                     string `json:"alias-subnet"`
	Ipaddr                          string `json:"ipaddr"`
	Dhcprejectfrom                  string `json:"dhcprejectfrom"`
	AdvDhcpPtTimeout                string `json:"adv_dhcp_pt_timeout"`
	AdvDhcpPtRetry                  string `json:"adv_dhcp_pt_retry"`
	AdvDhcpPtSelectTimeout          string `json:"adv_dhcp_pt_select_timeout"`
	AdvDhcpPtReboot                 string `json:"adv_dhcp_pt_reboot"`
	AdvDhcpPtBackoffCutoff          string `json:"adv_dhcp_pt_backoff_cutoff"`
	AdvDhcpPtInitialInterval        string `json:"adv_dhcp_pt_initial_interval"`
	AdvDhcpPtValues                 string `json:"adv_dhcp_pt_values"`
	AdvDhcpSendOptions              string `json:"adv_dhcp_send_options"`
	AdvDhcpRequestOptions           string `json:"adv_dhcp_request_options"`
	AdvDhcpRequiredOptions          string `json:"adv_dhcp_required_options"`
	AdvDhcpOptionModifiers          string `json:"adv_dhcp_option_modifiers"`
	AdvDhcpConfigAdvanced           string `json:"adv_dhcp_config_advanced"`
	AdvDhcpConfigFileOverride       string `json:"adv_dhcp_config_file_override"`
	AdvDhcpConfigFileOverridePath   string `json:"adv_dhcp_config_file_override_path"`
	Ipaddrv6                        string `json:"ipaddrv6"`
	Dhcp6Duid                       string `json:"dhcp6-duid"`
	Dhcp6IaPdLen                    string `json:"dhcp6-ia-pd-len"`
	AdvDhcp6PrefixSelectedInterface string `json:"adv_dhcp6_prefix_selected_interface"`
	Blockpriv                       string `json:"blockpriv"`
	Blockbogons                     string `json:"blockbogons"`
	Subnet                          string `json:"subnet"`
	Spoofmac                        string `json:"spoofmac"`
	Name                            string `json:"name"`
	Gateway                         string `json:"gateway"`
	Gatewayv6                       string `json:"gatewayv6"`
}
type InterfaceRequest struct {
	AdvDhcpConfigAdvanced         bool     `json:"adv_dhcp_config_advanced"`
	AdvDhcpConfigFileOverride     bool     `json:"adv_dhcp_config_file_override"`
	AdvDhcpConfigFileOverrideFile string   `json:"adv_dhcp_config_file_override_file,omitempty"`
	AdvDhcpOptionModifiers        string   `json:"adv_dhcp_option_modifiers,omitempty"`
	AdvDhcpPtBackoffCutoff        int      `json:"adv_dhcp_pt_backoff_cutoff,omitempty"`
	AdvDhcpPtInitialInterval      int      `json:"adv_dhcp_pt_initial_interval,omitempty"`
	AdvDhcpPtReboot               int      `json:"adv_dhcp_pt_reboot,omitempty"`
	AdvDhcpPtRetry                int      `json:"adv_dhcp_pt_retry,omitempty"`
	AdvDhcpPtSelectTimeout        int      `json:"adv_dhcp_pt_select_timeout,omitempty"`
	AdvDhcpPtTimeout              int      `json:"adv_dhcp_pt_timeout,omitempty"`
	AdvDhcpRequestOptions         string   `json:"adv_dhcp_request_options,omitempty"`
	AdvDhcpRequiredOptions        string   `json:"adv_dhcp_required_options,omitempty"`
	AdvDhcpSendOptions            string   `json:"adv_dhcp_send_options,omitempty"`
	AliasAddress                  string   `json:"alias-address,omitempty"`
	AliasSubnet                   int      `json:"alias-subnet,omitempty"`
	Apply                         bool     `json:"apply"`
	Blockbogons                   bool     `json:"blockbogons"`
	Blockpriv                     bool     `json:"blockpriv"`
	Descr                         string   `json:"descr,omitempty"`
	Dhcpcvpt                      int      `json:"dhcpcvpt,omitempty"`
	Dhcphostname                  string   `json:"dhcphostname,omitempty"`
	Dhcprejectfrom                []string `json:"dhcprejectfrom,omitempty"`
	Dhcpvlanenable                bool     `json:"dhcpvlanenable"`
	Enable                        bool     `json:"enable"`
	Gateway                       string   `json:"gateway,omitempty"`
	Gateway6Rd                    string   `json:"gateway-6rd,omitempty"`
	Gatewayv6                     string   `json:"gatewayv6,omitempty"`
	Id                            string   `json:"id"`
	If                            string   `json:"if"`
	Ipaddr                        string   `json:"ipaddr,omitempty"`
	Ipaddrv6                      string   `json:"ipaddrv6,omitempty"`
	Ipv6Usev4Iface                bool     `json:"ipv6usev4iface,omitempty"`
	Media                         string   `json:"media,omitempty"`
	Mss                           string   `json:"mss,omitempty"`
	Mtu                           int      `json:"mtu,omitempty"`
	Prefix6Rd                     string   `json:"prefix-6rd,omitempty"`
	Prefix6RdV4Plen               int      `json:"prefix-6rd-v4plen,omitempty"`
	Spoofmac                      string   `json:"spoofmac,omitempty"`
	Subnet                        int      `json:"subnet,omitempty"`
	Subnetv6                      string   `json:"subnetv6,omitempty"`
	Track6Interface               string   `json:"track6-interface,omitempty"`
	Track6PrefixIdHex             int      `json:"track6-prefix-id-hex,omitempty"`
	Type                          string   `json:"type,omitempty"`
	Type6                         string   `json:"type6,omitempty"`
}

type VLAN struct {
	If     string `json:"if"`
	Tag    string `json:"tag"`
	Pcp    string `json:"pcp"`
	Descr  string `json:"descr"`
	Vlanif string `json:"vlanif"`
}

type interfaceListResponse struct {
	apiResponse
	Data map[string]*Interface `json:"data"`
}

type vlanListResponse struct {
	apiResponse
	Data []*VLAN `json:"data"`
}

// ListInterfaces returns the interfaces
func (s InterfaceService) ListInterfaces(ctx context.Context) ([]*Interface, error) {
	response, err := s.client.get(ctx, interfaceEndpoint, nil)
	if err != nil {
		return nil, err
	}

	resp := new(interfaceListResponse)
	if err = json.Unmarshal(response, resp); err != nil {
		return nil, err
	}

	interfaces := make([]*Interface, 0, len(resp.Data))
	for interfaceName, interfaceDetails := range resp.Data {
		interfaceDetails.Name = interfaceName
		interfaces = append(interfaces, interfaceDetails)
	}
	return interfaces, nil
}

// ListVLANs returns the VLANs
func (s InterfaceService) ListVLANs(ctx context.Context) ([]*VLAN, error) {
	response, err := s.client.get(ctx, interfaceVLANEndpoint, nil)
	if err != nil {
		return nil, err
	}

	resp := new(vlanListResponse)
	if err = json.Unmarshal(response, resp); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

func (s InterfaceService) UpdateInterface(ctx context.Context, iface *InterfaceRequest) error {
	jsonData, err := json.Marshal(iface)
	if err != nil {
		return err
	}
	_, err = s.client.put(ctx, interfaceEndpoint, map[string]string{"id": iface.Id}, jsonData)
	if err != nil {
		return err
	}

	return nil
	//return s.Apply(ctx)

}

// Apply applies pending interface changes
func (s InterfaceService) Apply(ctx context.Context) error {
	_, err := s.client.post(ctx, interfaceApplyEndpoint, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

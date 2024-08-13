package pfapi

import (
	"encoding/json"
	"golang.org/x/exp/maps"
	"strconv"
)

const (
	aliasEndpoint          = "api/v1/firewall/alias"
	aliasEntryEndpoint     = "api/v1/firewall/alias/entity"
	ruleEndpoint           = "api/v1/firewall/rule"
	natPortForwardEndpoint = "api/v1/firewall/nat/port_forward"
	firewallApplyEndpoint  = "api/v1/firewall/apply"
)

type FirewallService service

func (s FirewallService) Apply() error {
	_, err := s.client.post(firewallApplyEndpoint, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

type FirewallAlias struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Address string `json:"address"`
	Descr   string `json:"descr"`
	Detail  string `json:"detail"`
}

type firewallAliasListResponse struct {
	apiResponse
	Data []*FirewallAlias `json:"data"`
}

func (s FirewallService) AliasesList() ([]*FirewallAlias, error) {
	response, err := s.client.get(aliasEndpoint, nil)
	if err != nil {
		return nil, err
	}

	resp := new(firewallAliasListResponse)
	if err = json.Unmarshal(response, resp); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

type FirewallAliasRequest struct {
	Address []string `json:"address"`
	Descr   string   `json:"descr"`
	Detail  []string `json:"detail"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
}

type firewallAliasRequestCreate struct {
	FirewallAliasRequest
	Apply bool `json:"apply"`
}

func (s FirewallService) AliasCreate(newAlias FirewallAliasRequest, apply bool) error {
	requestData := firewallAliasRequestCreate{
		FirewallAliasRequest: newAlias,
		Apply:                apply,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return err
	}
	_, err = s.client.post(aliasEndpoint, nil, jsonData)
	if err != nil {
		return err
	}
	return nil
}

func (s FirewallService) AliasDelete(aliasToDelete string, apply bool) error {
	_, err := s.client.delete(
		aliasEndpoint,
		map[string]string{
			"id":    aliasToDelete,
			"apply": strconv.FormatBool(apply),
		},
	)
	if err != nil {
		return err
	}
	return nil
}

type firewallAliasRequestUpdate struct {
	FirewallAliasRequest
	Apply bool   `json:"apply"`
	Id    string `json:"id"`
}

func (s FirewallService) AliasUpdate(aliasToUpdate string, newAliasData FirewallAliasRequest, apply bool) error {
	requestData := firewallAliasRequestUpdate{
		FirewallAliasRequest: newAliasData,
		Apply:                apply,
		Id:                   aliasToUpdate,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return err
	}
	_, err = s.client.put(aliasEndpoint, nil, jsonData)
	if err != nil {
		return err
	}
	return nil
}

type firewallAliasEntryRequestCreate struct {
	Address []string `json:"address"`
	Apply   bool     `json:"apply"`
	Detail  []string `json:"detail"`
	Name    string   `json:"name"`
}

func (s FirewallService) AliasEntryCreate(aliasName string, toAdd map[string]string, apply bool) error {
	newRequest := firewallAliasEntryRequestCreate{
		Address: maps.Keys(toAdd),
		Apply:   apply,
		Detail:  maps.Values(toAdd),
		Name:    aliasName,
	}
	jsonData, err := json.Marshal(newRequest)
	if err != nil {
		return err
	}
	_, err = s.client.post(aliasEntryEndpoint, nil, jsonData)
	if err != nil {
		return err
	}
	return nil
}
func (s FirewallService) AliasEntryDelete(aliasName string, address string, apply bool) error {
	_, err := s.client.delete(
		aliasEntryEndpoint,
		map[string]string{
			"name":    aliasName,
			"address": address,
			"apply":   strconv.FormatBool(apply),
		},
	)
	if err != nil {
		return err
	}
	return nil
}

type FirewallRule struct {
	Id           string            `json:"id"`
	Tracker      string            `json:"tracker"`
	Type         string            `json:"type"`
	Interface    string            `json:"interface"`
	Ipprotocol   string            `json:"ipprotocol"`
	Tag          string            `json:"tag"`
	Tagged       string            `json:"tagged"`
	Max          string            `json:"max"`
	MaxSrcNodes  string            `json:"max-src-nodes"`
	MaxSrcConn   string            `json:"max-src-conn"`
	MaxSrcStates string            `json:"max-src-states"`
	Statetimeout string            `json:"statetimeout"`
	Statetype    string            `json:"statetype"`
	Os           string            `json:"os"`
	Source       map[string]string `json:"source"`
	Destination  map[string]string `json:"destination"`
	Descr        string            `json:"descr"`
	Updated      struct {
		Time     string `json:"time"`
		Username string `json:"username"`
	} `json:"updated"`
	Created struct {
		Time     string `json:"time"`
		Username string `json:"username"`
	} `json:"created"`
}

type firewallRuleListResponse struct {
	apiResponse
	Data []*FirewallRule `json:"data"`
}

func (s FirewallService) RulesList() ([]*FirewallRule, error) {
	response, err := s.client.get(ruleEndpoint, nil)
	if err != nil {
		return nil, err
	}

	resp := new(firewallRuleListResponse)
	if err = json.Unmarshal(response, resp); err != nil {
		return nil, err
	}

	return resp.Data, nil
}

func (s FirewallService) RuleDelete(tracker int, apply bool) error {
	_, err := s.client.delete(
		ruleEndpoint,
		map[string]string{
			"tracker": strconv.Itoa(tracker),
			"apply":   strconv.FormatBool(apply),
		},
	)
	if err != nil {
		return err
	}
	return nil
}

type FirewallRuleRequest struct {
	AckQueue     string   `json:"ackqueue"`
	DefaultQueue string   `json:"defaultqueue"`
	Descr        string   `json:"descr"`
	Direction    string   `json:"direction"`
	Disabled     bool     `json:"disabled"`
	Dnpipe       string   `json:"dnpipe"`
	Dst          string   `json:"dst"`
	DstPort      string   `json:"dstport"`
	Floating     bool     `json:"floating"`
	Gateway      string   `json:"gateway"`
	IcmpType     []string `json:"icmptype"`
	Interface    []string `json:"interface"`
	IpProtocol   string   `json:"ipprotocol"`
	Log          bool     `json:"log"`
	Pdnpipe      string   `json:"pdnpipe"`
	Protocol     string   `json:"protocol"`
	Quick        bool     `json:"quick"`
	Sched        string   `json:"sched"`
	Src          string   `json:"src"`
	SrcPort      string   `json:"srcport"`
	StateType    string   `json:"statetype"`
	TcpFlagsAny  bool     `json:"tcpflags_any"`
	TcpFlags1    []string `json:"tcpflags1"`
	TcpFlags2    []string `json:"tcpflags2"`
	Top          bool     `json:"top"`
	Type         string   `json:"type"`
}

type firewallRuleRequestCreate struct {
	FirewallRuleRequest
	Apply bool `json:"apply"`
}

func (s FirewallService) RuleCreate(newRule FirewallRuleRequest, apply bool) error {
	requestData := firewallRuleRequestCreate{
		FirewallRuleRequest: newRule,
		Apply:               apply,
	}
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return err
	}
	_, err = s.client.post(ruleEndpoint, nil, jsonData)
	if err != nil {
		return err
	}
	return nil
}

type firewallRuleRequestUpdate struct {
	FirewallRuleRequest
	Apply   bool `json:"apply"`
	Tracker int  `json:"tracker"`
}

func (s FirewallService) RuleUpdate(ruleToUpdate int, newRuleData FirewallRuleRequest, apply bool) error {
	requestData := firewallRuleRequestUpdate{
		FirewallRuleRequest: newRuleData,
		Apply:               apply,
		Tracker:             ruleToUpdate,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return err
	}
	_, err = s.client.put(ruleEndpoint, nil, jsonData)
	if err != nil {
		return err
	}
	return nil
}

type FirewallRuleNatPortForwardDestination struct {
	Network string `json:"network"`
	Port    string `json:"port"`
}
type FirewallRuleNatPortForward struct {
	Index            int                                    `json:"-"`
	Source           map[string]interface{}                 `json:"source"`
	Destination      *FirewallRuleNatPortForwardDestination `json:"destination"`
	IpProtocol       string                                 `json:"ipprotocol"`
	Protocol         string                                 `json:"protocol"`
	Target           string                                 `json:"target"`
	LocalPort        string                                 `json:"local-port"`
	Interface        string                                 `json:"interface"`
	Descr            string                                 `json:"descr"`
	AssociatedRuleId string                                 `json:"associated-rule-id"`
}
type FirewallRuleNatPortForwardRequest struct {
	Descr         string `json:"descr"`
	Disabled      bool   `json:"disabled"`
	Dst           string `json:"dst"`
	DstPort       string `json:"dstport"`
	Interface     string `json:"interface"`
	LocalPort     string `json:"local-port"`
	Natreflection string `json:"natreflection"`
	Nordr         string `json:"nordr"`
	Nosync        bool   `json:"nosync"`
	Protocol      string `json:"protocol"`
	Src           string `json:"src"`
	SrcPort       string `json:"srcport"`
	Target        string `json:"target"`
	Top           bool   `json:"top"`
}
type firewallRuleNatPortForwardCreateRequest struct {
	FirewallRuleNatPortForwardRequest
	Apply bool `json:"apply"`
}

func (s FirewallService) NatRulePortForwardCreate(rule FirewallRuleNatPortForwardRequest, apply bool) error {
	requestData := firewallRuleNatPortForwardCreateRequest{
		FirewallRuleNatPortForwardRequest: rule,
		Apply:                             apply,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return err
	}
	_, err = s.client.post(natPortForwardEndpoint, nil, jsonData)
	if err != nil {
		return err
	}
	return nil
}

func (s FirewallService) NatRulePortForwardCreateSimple(protocol string, port string, localIp string, localPort string, src string, description string) error {

	if "" == src {
		src = "any"
	}
	rule := FirewallRuleNatPortForwardRequest{
		Descr:         description,
		Disabled:      false,
		Dst:           "wanip",
		DstPort:       port,
		Interface:     "wan",
		LocalPort:     localPort,
		Natreflection: "disable",
		Nordr:         "",
		Nosync:        false,
		Protocol:      protocol,
		Src:           src,
		SrcPort:       "any",
		Target:        localIp,
		Top:           false,
	}

	return s.NatRulePortForwardCreate(rule, true)
}

type firewallNatRulePortForwardListResponse struct {
	apiResponse
	Data []FirewallRuleNatPortForward `json:"data"`
}

func (s FirewallService) NatRulePortForwardList() (rules []FirewallRuleNatPortForward, err error) {

	response, err := s.client.get(natPortForwardEndpoint, nil)
	if err != nil {
		return nil, err
	}

	resp := new(firewallNatRulePortForwardListResponse)
	if err = json.Unmarshal(response, resp); err != nil {
		return nil, err
	}

	for index, rule := range resp.Data {
		rule.Index = index
		rules = append(rules, rule)
	}
	return
}
func (s FirewallService) NatRulePortForwardFirst(port string, protocol string, src string) (rule *FirewallRuleNatPortForward, err error) {
	rules, err := s.NatRulePortForwardList()
	if nil != err {
		return
	}
	for _, r := range rules {
		if port == r.Destination.Port && ("" == protocol || r.Protocol == protocol) {
			if "" == src {
				rule = &r
				return
			} else {
				for _, addr := range r.Source {
					if addr == src {
						rule = &r
						return
					}

				}
			}

		}
	}
	return
}

func (s FirewallService) NatRulePortForwardDelete(index int, apply bool) error {
	_, err := s.client.delete(
		natPortForwardEndpoint,
		map[string]string{
			"id":    strconv.Itoa(index),
			"apply": strconv.FormatBool(apply),
		},
	)
	if err != nil {
		return err
	}
	return nil
}
func (s FirewallService) NatRulePortForwardDeleteSimple(port string, protocol string, src string) (err error) {
	for {
		rule, err1 := s.NatRulePortForwardFirst(port, protocol, src)
		if nil != err1 {
			err = err1
			return
		}
		if nil == rule {
			return
		}

		err1 = s.NatRulePortForwardDelete(rule.Index, true)
		if nil != err1 {
			err = err1
			return
		}
	}
	return

}

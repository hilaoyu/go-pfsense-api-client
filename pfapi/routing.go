package pfapi

import (
	"context"
	"encoding/json"
	"strconv"
)

const (
	gatewayEndpoint        = "api/v1/routing/gateway"
	defaultGatewayEndpoint = "api/v1/routing/gateway/default"
	routingApplyEndpoint   = "api/v1/routing/apply"
)

// RoutingService provides routing API methods
type RoutingService service

// Gateway represents a single routing gateway
type Gateway struct {
	Dynamic         bool        `json:"dynamic"`
	IpProtocol      string      `json:"ipprotocol"`
	Gateway         string      `json:"gateway"`
	Interface       string      `json:"interface"`
	FriendlyIface   string      `json:"friendlyiface"`
	FriendlyIfDescr string      `json:"friendlyifdescr"`
	Name            string      `json:"name"`
	Attribute       StringOrInt `json:"attribute"`
	IsDefaultGW     bool        `json:"isdefaultgw"`
	Monitor         string      `json:"monitor"`
	Descr           string      `json:"descr"`
	TierName        string      `json:"tiername"`
	Id              int         `json:"id"`
}

type gatewayListResponse struct {
	apiResponse
	Data map[string]*Gateway `json:"data"`
}

// ListGateways returns the gateways
func (s RoutingService) ListGateways(ctx context.Context) ([]*Gateway, error) {
	response, err := s.client.get(ctx, gatewayEndpoint, nil)
	if err != nil {
		return nil, err
	}

	resp := new(gatewayListResponse)
	if err = json.Unmarshal(response, resp); err != nil {
		return nil, err
	}

	//return maps.Values(resp.Data), nil

	gateways := make([]*Gateway, 0, len(resp.Data))
	i := 0
	for _, gw := range resp.Data {
		gw.Id = i
		gateways = append(gateways, gw)
		i++
	}
	return gateways, nil

}

// GatewayRequest represents a single gateway to be created or modified. This
// type is use for creations and updates.
type GatewayRequest struct {
	ActionDisable  bool   `json:"action_disable,omitempty"`
	AlertInterval  int    `json:"alert_interval,omitempty"`
	Apply          bool   `json:"apply"`
	DataPayload    int    `json:"data_payload,omitempty"`
	Descr          string `json:"descr,omitempty"`
	Disabled       bool   `json:"disabled,omitempty"`
	ForceDown      bool   `json:"force_down,omitempty"`
	Gateway        string `json:"gateway,omitempty"`
	Interface      string `json:"interface,omitempty"`
	Interval       int    `json:"interval,omitempty"`
	IpProtocol     string `json:"ipprotocol,omitempty"`
	LatencyHigh    int    `json:"latencyhigh,omitempty"`
	LatencyLow     int    `json:"latencylow,omitempty"`
	LossInterval   int    `json:"loss_interval,omitempty"`
	LossHigh       int    `json:"losshigh,omitempty"`
	LossLow        int    `json:"losslow,omitempty"`
	Monitor        string `json:"monitor,omitempty"`
	MonitorDisable bool   `json:"monitor_disable,omitempty"`
	Name           string `json:"name,omitempty"`
	TimePeriod     int    `json:"time_period,omitempty"`
	Weight         int    `json:"weight,omitempty"`
	Id             int    `json:"id"`
}

// CreateGateway creates a new Gateway
func (s RoutingService) CreateGateway(ctx context.Context, newGateway GatewayRequest) error {
	jsonData, err := json.Marshal(newGateway)
	if err != nil {
		return err
	}
	_, err = s.client.post(ctx, gatewayEndpoint, nil, jsonData)
	if err != nil {
		return err
	}
	return nil
}

// DeleteGateway deletes a Gateway
func (s RoutingService) DeleteGateway(ctx context.Context, gatewayID int) error {
	_, err := s.client.delete(ctx, gatewayEndpoint, map[string]string{"id": strconv.Itoa(gatewayID)})
	if err != nil {
		return err
	}
	return nil
}

// UpdateGateway modifies a existing gateway
func (s RoutingService) UpdateGateway(ctx context.Context, gatewayToUpdate GatewayRequest) error {
	jsonData, err := json.Marshal(gatewayToUpdate)
	if err != nil {
		return err
	}
	_, err = s.client.put(ctx, gatewayEndpoint, nil, jsonData)
	if err != nil {
		return err
	}
	return nil
}

type DefaultGatewayRequest struct {
	DefaultGW4 string `json:"defaultgw4"`
	DefaultGW6 string `json:"defaultgw6"`
	Apply      bool   `json:"apply"`
}

// SetDefaultGateway sets the default gateway
func (s RoutingService) SetDefaultGateway(ctx context.Context, newDefaultGateway DefaultGatewayRequest) error {
	jsonData, err := json.Marshal(newDefaultGateway)
	if err != nil {
		return err
	}
	_, err = s.client.put(ctx, defaultGatewayEndpoint, nil, jsonData)
	if err != nil {
		return err
	}
	return nil
}

// Apply applies pending routing changes
func (s RoutingService) Apply(ctx context.Context) error {
	_, err := s.client.post(ctx, routingApplyEndpoint, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

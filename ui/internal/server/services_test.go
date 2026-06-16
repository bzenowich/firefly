package server

import (
	"net/url"
	"testing"
)

func TestServiceCRUDAndDeleteGuard(t *testing.T) {
	c, store := newTestServer(t)
	svcID := makeService(t, c, store)

	// Update edits in place, keeping the ID.
	upd := url.Values{"name": {"web"}, "ip": {"192.168.1.11"}, "port": {"8443"}, "proto": {"tcp"}}
	if loc := c.post(t, "/services/"+svcID, upd); loc.Query().Get("err") != "" {
		t.Fatalf("service update: %s", loc.Query().Get("err"))
	}
	if svc := store.Get().Services[0]; svc.ID != svcID || svc.IP != "192.168.1.11" || svc.Port != 8443 {
		t.Fatalf("update not applied: %+v", svc)
	}

	// A port forward references the service; deleting it must be refused.
	c.post(t, "/nat/forwards", url.Values{
		"name": {"web"}, "service_id": {svcID}, "wan_port": {"443"}, "enabled": {"on"},
	})
	if loc := c.post(t, "/services/"+svcID+"/delete", nil); loc.Query().Get("err") == "" {
		t.Fatal("deleting an in-use service should be refused")
	}
	if len(store.Get().Services) != 1 {
		t.Fatal("in-use service must not be deleted")
	}

	// Remove the forward, then the service deletes cleanly.
	id := store.Get().NAT.PortForwards[0].ID
	c.post(t, "/nat/forwards/"+id+"/delete", nil)
	if loc := c.post(t, "/services/"+svcID+"/delete", nil); loc.Query().Get("err") != "" {
		t.Fatalf("service delete: %s", loc.Query().Get("err"))
	}
	if len(store.Get().Services) != 0 {
		t.Fatal("service not deleted")
	}
}

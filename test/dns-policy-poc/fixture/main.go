package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"net/http"
	"os"
)

func main() {
	dns.HandleFunc(".", func(w dns.ResponseWriter, q *dns.Msg) {
		r := new(dns.Msg)
		r.SetReply(q)
		for _, v := range q.Question {
			if v.Qtype == dns.TypeA {
				r.Answer = append(r.Answer, &dns.A{Hdr: dns.RR_Header{Name: v.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: net.ParseIP(os.Getenv("POD_IP"))})
			}
		}
		w.WriteMsg(r)
	})
	go func() { log.Fatal((&dns.Server{Addr: ":53", Net: "udp"}).ListenAndServe()) }()
	go func() { log.Fatal((&dns.Server{Addr: ":53", Net: "tcp"}).ListenAndServe()) }()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "dns-policy-poc-ok") })
	go http.ListenAndServe(":8081", nil)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

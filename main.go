package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"time"

	flags "github.com/jessevdk/go-flags"
	"layeh.com/radius"
	"layeh.com/radius/rfc2759"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/vendors/microsoft"
)

func main() {
	var cmdOpts CmdOpts

	var parser = flags.NewParser(&cmdOpts, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		os.Exit(0)
	}

	switch cmdOpts.Proto {
	case "pap":
		pap_auth(cmdOpts)
	case "mschapv2":
		mschapv2_auth(cmdOpts)
	default:
		fmt.Println("Check authentication protocol parameter. Possible values: pap, mschapv2")
		os.Exit(1)
	}
}

func pap_auth(o CmdOpts) {
	packet := radius.New(radius.CodeAccessRequest, []byte(o.Secret))
	_ = rfc2865.UserName_SetString(packet, o.User)
	_ = rfc2865.UserPassword_SetString(packet, o.Password)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := radius.Exchange(ctx, packet, o.Address)
	if err != nil {
		log.Fatal(err)
	}
	print_packet(r)
}

func mschapv2_auth(o CmdOpts) {
	n := 16
	authenticatorChallenge := make([]byte, n)
	peerChallenge := make([]byte, n)
	_, err := rand.Read(authenticatorChallenge)
	if err != nil {
		return
	}
	_, err = rand.Read(peerChallenge)
	if err != nil {
		return
	}
	got, err := rfc2759.GenerateNTResponse(authenticatorChallenge, peerChallenge, []byte(o.User), []byte(o.Password))
	if err != nil {
		return
	}
	packet := radius.New(radius.CodeAccessRequest, []byte(o.Secret))
	err = rfc2865.UserName_SetString(packet, o.User)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = microsoft.MSCHAPChallenge_Set(packet, authenticatorChallenge)
	if err != nil {
		fmt.Println(err)
		return
	}

	// https://tools.ietf.org/html/rfc2548#2.3.2. MS-CHAP2-Response
	resp := make([]byte, 0, 50)
	resp = append(resp, '1', '0')
	resp = append(resp, peerChallenge...)
	resp = append(resp, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
	resp = append(resp, got...)

	err = microsoft.MSCHAP2Response_Add(packet, resp)
	if err != nil {
		fmt.Println(err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, err := radius.Exchange(ctx, packet, o.Address)
	if err != nil {
		fmt.Println(err)
		return
	}
	print_packet(r)

}

func print_packet(p *radius.Packet) {
	fmt.Printf("\nResponse contents\n\n")
	fmt.Printf("Code: %d, %s\n", p.Code, p.Code.String())
	v := rfc2865.ServiceType_Get(p).String()
	fmt.Println("Service Type: ", v)
	v = rfc2865.FramedProtocol_Get(p).String()
	fmt.Println("Framed-Protocol: ", v)
	v = rfc2865.FramedIPAddress_Get(p).String()
	fmt.Println("Framed-IPAddress: ", v)
	v = rfc2865.FramedIPNetmask_Get(p).String()
	fmt.Println("Framed-Netmask: ", v)
	v = rfc2865.FramedRouting_Get(p).String()
	fmt.Println("Framed-Routing: ", v)
	va := rfc2865.FramedRoute_Get(p)
	for _, el := range va {
		fmt.Println("Framed-Route: ", string(el))
	}
	ip := microsoft.MSPrimaryDNSServer_Get(p)
	fmt.Println("MS-Primary-DNS-Server: ", ip.String())
	ip = microsoft.MSSecondaryDNSServer_Get(p)
	fmt.Println("MS-Secondary-DNS-Server: ", ip.String())

	fmt.Println("\nAll attributes:")
	for i := range p.Attributes {
		a := p.Attributes[i]
		fmt.Printf("Type ID: %d, Value:  %s\n", a.Type, radius.String(a.Attribute))
	}

}

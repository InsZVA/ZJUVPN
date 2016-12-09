package main

import (
	"flag"
	"math/rand"
	"os"
	"os/signal"
	"sync"

	"github.com/inszva/gol2tp/network"
	"github.com/inszva/gol2tp/protocol"
)

func main() {
	localAddr := flag.String("l", "222.205.47.118", "本机有线网卡的ip地址")
	lnsAddr := flag.String("r", "10.5.1.9", "LNS服务器地址")
	username := flag.String("u", "3140104024@c", "用户名，例如3140104024@c，@c表示30元，@a表示10元，@d表示50元")
	password := flag.String("p", "thefirstgeek", "密码")
	flag.Parse()
	session := protocol.L2TPSession{
		RAddr:          *lnsAddr,
		LAddr:          *localAddr,
		LTunnelId:      uint16(rand.Uint32() >> 16),
		LReceiveWindow: 8,
		LSessionId:     uint16(rand.Uint32() >> 16),
	}

	session.CreateConn()
	session.CreateTunnel()
	session.CreateSession()
	ppp := protocol.PPPSession{
		L2tpSession:  &session,
		LMagicNumber: rand.Uint32(),
		Username:     *username,
		Password:     *password,
	}
	ppp.LCPContact()
	ppp.CHAPContact()
	ppp.IPCPContact()

	wp := sync.WaitGroup{}
	// VPN Transfrom
	wp.Add(1)
	go func() {
		network.NewCard(&ppp)
		wp.Done()
	}()

	// Clean
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	<-c
	network.Exit()
	wp.Wait()

	ppp.Terminate()
	session.CDN()
	session.StopCCN()
}

/*
BOOL   SetIP(LPCTSTR   lpszAdapterName,   int   nIndex,   LPCTSTR   pIPAddress,   LPCTSTR   pNetMask,   LPCTSTR   pNetGate)
{
HKEY   hKey;
CString   strKeyName   =   "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\ ";
strKeyName   +=   lpszAdapterName;
if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
strKeyName,
0,
KEY_WRITE,
&hKey)   !=   ERROR_SUCCESS)
return   FALSE;

char   mszIPAddress[100];
char   mszNetMask[100];
char   mszNetGate[100];

strncpy(mszIPAddress,   pIPAddress,   98);
strncpy(mszNetMask,   pNetMask,   98);
strncpy(mszNetGate,   pNetGate,   98);

int   nIP,   nMask,   nGate;

nIP   =   strlen(mszIPAddress);
nMask   =   strlen(mszNetMask);
nGate   =   strlen(mszNetGate);

*(mszIPAddress   +   nIP   +   1)   =   0x00;
nIP   +=   2;

*(mszNetMask   +   nMask   +   1)   =   0x00;
nMask   +=   2;

*(mszNetGate   +   nGate   +   1)   =   0x00;
nGate   +=   2;

RegSetValueEx(hKey,   "IPAddress ",   0,   REG_MULTI_SZ,   (unsigned   char*)mszIPAddress,   nIP);
RegSetValueEx(hKey,   "SubnetMask ",   0,   REG_MULTI_SZ,   (unsigned   char*)mszNetMask,   nMask);
RegSetValueEx(hKey,   "DefaultGateway ",   0,   REG_MULTI_SZ,   (unsigned   char*)mszNetGate,   nGate);

RegCloseKey(hKey);

//通知IP地址改变
BOOL bResult   =   FALSE;
HINSTANCE hDhcpDll;
DHCPNOTIFYPROC pDhcpNotifyProc;
WCHAR   wcAdapterName[256];

MultiByteToWideChar(CP_ACP,   0,   lpszAdapterName,   -1,   wcAdapterName,256);

if((hDhcpDll   =   LoadLibrary( "dhcpcsvc "))   ==   NULL)
return   FALSE;

if((pDhcpNotifyProc   =   (DHCPNOTIFYPROC)GetProcAddress(hDhcpDll,   "DhcpNotifyConfigChange "))   !=   NULL)
if((pDhcpNotifyProc)(NULL,   wcAdapterName,   TRUE,   nIndex,   inet_addr(pIPAddress),   inet_addr(pNetMask),   0)   ==   ERROR_SUCCESS)
bResult   =   TRUE;

FreeLibrary(hDhcpDll);

return   TRUE;
}
*/

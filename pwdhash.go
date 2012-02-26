package main

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

const pwdprefix = "@@"
const minlen = 5

func trimurl(host string) string {
	host = strings.Replace(host, "http://", "", 1)
	host = strings.Replace(host, "https://", "", 1)
	if slash := strings.Index(host, "/"); slash >= 0 {
		host = host[:slash]
	}

	list := strings.Split(host, ".")
	if len(list) > 2 {
		host = list[len(list)-2] + "." + list[len(list)-1]
		domains := map[string]bool{"ab.ca": true, "ac.ac": true, "ac.at": true, "ac.be": true, "ac.cn": true, "ac.il": true, "ac.in": true, "ac.jp": true, "ac.kr": true, "ac.nz": true, "ac.th": true, "ac.uk": true, "ac.za": true, "adm.br": true, "adv.br": true, "agro.pl": true, "ah.cn": true, "aid.pl": true, "alt.za": true, "am.br": true, "arq.br": true, "art.br": true, "arts.ro": true, "asn.au": true, "asso.fr": true, "asso.mc": true, "atm.pl": true, "auto.pl": true, "bbs.tr": true, "bc.ca": true, "bio.br": true, "biz.pl": true, "bj.cn": true, "br.com": true, "cn.com": true, "cng.br": true, "cnt.br": true, "co.ac": true, "co.at": true, "co.il": true, "co.in": true, "co.jp": true, "co.kr": true, "co.nz": true, "co.th": true, "co.uk": true, "co.za": true, "com.au": true, "com.br": true, "com.cn": true, "com.ec": true, "com.fr": true, "com.hk": true, "com.mm": true, "com.mx": true, "com.pl": true, "com.ro": true, "com.ru": true, "com.sg": true, "com.tr": true, "com.tw": true, "cq.cn": true, "cri.nz": true, "de.com": true, "ecn.br": true, "edu.au": true, "edu.cn": true, "edu.hk": true, "edu.mm": true, "edu.mx": true, "edu.pl": true, "edu.tr": true, "edu.za": true, "eng.br": true, "ernet.in": true, "esp.br": true, "etc.br": true, "eti.br": true, "eu.com": true, "eu.lv": true, "fin.ec": true, "firm.ro": true, "fm.br": true, "fot.br": true, "fst.br": true, "g12.br": true, "gb.com": true, "gb.net": true, "gd.cn": true, "gen.nz": true, "gmina.pl": true, "go.jp": true, "go.kr": true, "go.th": true, "gob.mx": true, "gov.br": true, "gov.cn": true, "gov.ec": true, "gov.il": true, "gov.in": true, "gov.mm": true, "gov.mx": true, "gov.sg": true, "gov.tr": true, "gov.za": true, "govt.nz": true, "gs.cn": true, "gsm.pl": true, "gv.ac": true, "gv.at": true, "gx.cn": true, "gz.cn": true, "hb.cn": true, "he.cn": true, "hi.cn": true, "hk.cn": true, "hl.cn": true, "hn.cn": true, "hu.com": true, "idv.tw": true, "ind.br": true, "inf.br": true, "info.pl": true, "info.ro": true, "iwi.nz": true, "jl.cn": true, "jor.br": true, "jpn.com": true, "js.cn": true, "k12.il": true, "k12.tr": true, "lel.br": true, "ln.cn": true, "ltd.uk": true, "mail.pl": true, "maori.nz": true, "mb.ca": true, "me.uk": true, "med.br": true, "med.ec": true, "media.pl": true, "mi.th": true, "miasta.pl": true, "mil.br": true, "mil.ec": true, "mil.nz": true, "mil.pl": true, "mil.tr": true, "mil.za": true, "mo.cn": true, "muni.il": true, "nb.ca": true, "ne.jp": true, "ne.kr": true, "net.au": true, "net.br": true, "net.cn": true, "net.ec": true, "net.hk": true, "net.il": true, "net.in": true, "net.mm": true, "net.mx": true, "net.nz": true, "net.pl": true, "net.ru": true, "net.sg": true, "net.th": true, "net.tr": true, "net.tw": true, "net.za": true, "nf.ca": true, "ngo.za": true, "nm.cn": true, "nm.kr": true, "no.com": true, "nom.br": true, "nom.pl": true, "nom.ro": true, "nom.za": true, "ns.ca": true, "nt.ca": true, "nt.ro": true, "ntr.br": true, "nx.cn": true, "odo.br": true, "on.ca": true, "or.ac": true, "or.at": true, "or.jp": true, "or.kr": true, "or.th": true, "org.au": true, "org.br": true, "org.cn": true, "org.ec": true, "org.hk": true, "org.il": true, "org.mm": true, "org.mx": true, "org.nz": true, "org.pl": true, "org.ro": true, "org.ru": true, "org.sg": true, "org.tr": true, "org.tw": true, "org.uk": true, "org.za": true, "pc.pl": true, "pe.ca": true, "plc.uk": true, "ppg.br": true, "presse.fr": true, "priv.pl": true, "pro.br": true, "psc.br": true, "psi.br": true, "qc.ca": true, "qc.com": true, "qh.cn": true, "re.kr": true, "realestate.pl": true, "rec.br": true, "rec.ro": true, "rel.pl": true, "res.in": true, "ru.com": true, "sa.com": true, "sc.cn": true, "school.nz": true, "school.za": true, "se.com": true, "se.net": true, "sh.cn": true, "shop.pl": true, "sk.ca": true, "sklep.pl": true, "slg.br": true, "sn.cn": true, "sos.pl": true, "store.ro": true, "targi.pl": true, "tj.cn": true, "tm.fr": true, "tm.mc": true, "tm.pl": true, "tm.ro": true, "tm.za": true, "tmp.br": true, "tourism.pl": true, "travel.pl": true, "tur.br": true, "turystyka.pl": true, "tv.br": true, "tw.cn": true, "uk.co": true, "uk.com": true, "uk.net": true, "us.com": true, "uy.com": true, "vet.br": true, "web.za": true, "web.com": true, "www.ro": true, "xj.cn": true, "xz.cn": true, "yk.ca": true, "yn.cn": true, "za.com": true}
		if _, ok := domains[host]; ok {
			host = list[len(list)-3] + "." + host
		}
	}

	return host
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "Usage: pwdhash <password> <domain>")
		return
	}
	pwd := os.Args[1]
	host := trimurl(os.Args[2])

	if strings.HasPrefix(pwd, pwdprefix) {
		pwd = pwd[len(pwdprefix):]
	}
	if len(pwd) < minlen {
		fmt.Fprintln(os.Stderr, "Error: Password is too short.")
		return
	}

	hm := hmac.New(md5.New, []byte(pwd))
	hm.Write([]byte(host))
	hash := hm.Sum(nil)

	buf := make([]byte, base64.StdEncoding.EncodedLen(len(hash)))
	base64.StdEncoding.Encode(buf, hash)

	nonalnum := strings.IndexFunc(pwd, isNotAlNum) >= 0
	pwdhash := constrain(string(buf), len(pwd)+len(pwdprefix), nonalnum)
	fmt.Println(pwdhash)
}

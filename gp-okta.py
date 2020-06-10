#!/usr/bin/env python3
"""
   The MIT License (MIT)

   Copyright (C) 2018 Andris Raugulis (moo@arthepsy.eu)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
"""
import base64
import getpass
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from urllib.parse import urljoin

import requests
from lxml import etree

verbose = False


def to_b(v):
    return v if isinstance(v, bytes) else v.encode("utf-8")


def log(s):
    if verbose:
        print(f"[INFO] {s}")


def dbg(h, *xs):
    if not verbose:
        return
    print(f"[DEBUG] {h}:")
    for x in xs:
        print(f"[DEBUG] {x}")
    print("[DEBUG]----------------------------------------------")


def err(s):
    print(f"[ERROR] {s}")
    sys.exit(1)


def parse_xml(xml):
    try:
        xml = bytes(bytearray(xml, encoding="utf-8"))
        parser = etree.XMLParser(ns_clean=True, recover=True)
        return etree.fromstring(xml, parser)
    except Exception as e:
        err("failed to parse xml: " + e)


def parse_html(html):
    try:
        parser = etree.HTMLParser()
        return etree.fromstring(html, parser)
    except Exception as e:
        err("failed to parse html: " + e)


def parse_rjson(r):
    try:
        return r.json()
    except Exception as e:
        err("failed to parse json: " + e)


def parse_form(html, current_url=None):
    xform = html.find(".//form")
    url = xform.attrib.get("action", "").strip()

    if not url.startswith("http") and current_url:
        url = urljoin(current_url, url)

    data = {}
    for xinput in html.findall(".//input"):
        k = xinput.attrib.get("name", "").strip()
        v = xinput.attrib.get("value", "").strip()

        if len(k) > 0 and len(v) > 0:
            data[k] = v

    return url, data


def load_conf(cf):
    conf = {}
    keys = ["vpn_url", "username", "password", "okta_url"]

    if isinstance(cf, bytes):
        cf = cf.decode("utf-8")

    line_nr = 0
    for rline in cf.split("\n"):
        line_nr += 1
        line = rline.strip()
        mx = re.match(r"^\s*([^=\s]+)\s*=\s*(.*?)\s*(?:#\s+.*)?\s*$", line)

        if mx:
            k, v = mx.group(1).lower(), mx.group(2)

            if k.startswith("#"):
                continue

            for q in "\"'":
                if re.match(r"^{0}.*{0}$".format(q), v):
                    v = v[1:-1]

            conf[k] = v
            conf[f"{k}.line"] = line_nr

    for k, v in os.environ.items():
        k = k.lower()

        if k.startswith("gp_"):
            k = k[3:]

            if len(k) == 0:
                continue

            conf[k] = v.strip()

    if len(conf.get("username", "").strip()) == 0:
        conf["username"] = input("username: ").strip()

    if len(conf.get("password", "").strip()) == 0:
        conf["password"] = getpass.getpass("password: ").strip()

    for k in keys:
        if k not in conf:
            err(f"missing configuration key: {k}")
        else:
            if len(conf[k].strip()) == 0:
                err(f"empty configuration key: {k}")

    conf["debug"] = conf.get("debug", "").lower() in ["1", "true"]

    return conf


def mfa_priority(conf, ftype, fprovider):
    if ftype == "token:software:totp":
        ftype = "totp"

    assert ftype in ["totp", "sms", "push"]

    mfa_order = conf.get("mfa_order", "")
    if ftype in mfa_order:
        priority = (10 - mfa_order.index(ftype)) * 100
    else:
        priority = 0

    value = conf.get(f"{ftype}.{fprovider}")
    if ftype == "sms":
        if not (value or "").lower() in ["1", "true"]:
            value = None

    line_nr = conf.get(f"{ftype}.{fprovider}.line", 0)

    if value is None:
        priority += 0
    elif len(value) == 0:
        priority += 128 - line_nr
    else:
        priority += 512 - line_nr

    return priority


def get_redirect_url(conf, c, current_url=None):
    rx_base_url = re.search(r"var\s*baseUrl\s*=\s*\'([^\']+)\'", c)
    rx_from_uri = re.search(r"var\s*fromUri\s*=\s*\'([^\']+)\'", c)

    if not rx_from_uri:
        dbg(conf.get("debug"), "not found", "formUri")
        return None

    from_uri = to_b(rx_from_uri.group(1)).decode("unicode_escape").strip()

    if from_uri.startswith("http"):
        return from_uri

    if not rx_base_url:
        dbg(conf.get("debug"), "not found", "baseUri")

        if current_url:
            return urljoin(current_url, from_uri)

        return from_uri

    base_url = to_b(rx_base_url.group(1)).decode("unicode_escape").strip()

    return base_url + from_uri


def send_req(conf, s, name, url, data, **kwargs):
    dbg(conf.get("debug"), f"{name}.request", url)

    if kwargs.get("get"):
        log("we must send a get")

    do_json = True if kwargs.get("json") else False
    headers = {}

    if do_json:
        data = json.dumps(data)
        headers["Accept"] = "application/json"
        headers["Content-Type"] = "application/json"

    if kwargs.get("get"):
        r = s.get(url, headers=headers)
    else:
        r = s.post(url, data=data, headers=headers)

    hdump = "\n".join([k + ": " + v for k, v in sorted(r.headers.items())])
    rr = f"status: {r.status_code}\n\n{hdump}\n\n{r.text}"

    if r.status_code != 200:
        err("okta {0} request failed. {0}".format(rr))

    dbg(conf.get("debug"), f"{name}.response", rr)

    if do_json:
        return r.headers, parse_rjson(r)

    return r.headers, r.text


def paloalto_prelogin_post(conf, s, again=False):
    log("prelogin request")
    url = "{}/global-protect/prelogin.esp".format(conf.get("vpn_url"))

    if again:
        url = "{}/ssl-vpn/prelogin.esp".format(conf.get("vpn_url"))

    data = {
        "clientVer": "4100",
        "clientos": "Windows",
        "clientgpversion": "4.1.0.98",
        "computer": "DESKTOP",
        "os-version": "Microsoft Windows 10 Pro, 64-bit",
        "ipv6-support": "yes",
    }

    _, c = send_req(conf, s, "getconfig", url, data)
    x = parse_xml(c)
    saml_req = x.find(".//saml-request")

    if saml_req is None:
        saml_req = x.find(".//saml-auth-method")

    if saml_req is None:
        err("did not find saml request")

    if len(saml_req.text.strip()) == 0:
        err("empty saml request")

    try:
        saml_raw = base64.b64decode(saml_req.text)
    except Exception as e:
        err("failed to decode saml request: " + e)

    dbg(conf.get("debug"), "prelogin.decoded", saml_raw)
    saml_xml = parse_html(saml_raw)

    return saml_xml


def paloalto_prelogin(conf, s, again=False):
    log("prelogin request")
    url = "{}/global-protect/prelogin.esp".format(conf.get("vpn_url"))

    if again:
        url = "{}/ssl-vpn/prelogin.esp".format(conf.get("vpn_url"))
    else:
        url = "{}/global-protect/prelogin.esp".format(conf.get("vpn_url"))

    _, c = send_req(conf, s, "prelogin", url, {}, get=True)
    x = parse_xml(c)
    saml_req = x.find(".//saml-request")

    if saml_req is None:
        saml_req = x.find(".//saml-auth-method")

    if saml_req is None:
        err("did not find saml request")

    if len(saml_req.text.strip()) == 0:
        err("empty saml request")

    try:
        saml_raw = base64.b64decode(saml_req.text)
    except Exception as e:
        err("failed to decode saml request: " + e)

    dbg(conf.get("debug"), "prelogin.decoded", saml_raw)
    saml_xml = parse_html(saml_raw)

    return saml_xml


def okta_saml(conf, s, saml_xml):
    log("okta saml request")
    url, data = parse_form(saml_xml)
    _, c = send_req(conf, s, "saml", url, data)
    redirect_url = get_redirect_url(conf, c, url)

    if redirect_url is None:
        err("did not find redirect url")

    return redirect_url


def okta_auth(conf, s):
    log("okta auth request")
    url = "{}/api/v1/authn".format(conf.get("okta_url"))
    data = {
        "username": conf.get("username"),
        "password": conf.get("password"),
        "options": {
            "warnBeforePasswordExpired": True,
            "multiOptionalFactorEnroll": True,
        },
    }

    _, j = send_req(conf, s, "auth", url, data, json=True)
    status = j.get("status", "").strip()
    dbg(conf.get("debug"), "status", status)

    if status.lower() == "success":
        session_token = j.get("sessionToken", "").strip()
    elif status.lower() == "mfa_required":
        session_token = okta_mfa(conf, s, j)
    else:
        print(j)
        err("unknown status")

    if len(session_token) == 0:
        err("empty session token")

    return session_token


def okta_mfa(conf, s, j):
    state_token = j.get("stateToken", "").strip()

    if len(state_token) == 0:
        err("empty state token")

    factors_json = j.get("_embedded", {}).get("factors", [])

    if len(factors_json) == 0:
        err("no factors found")

    factors = []
    for factor in factors_json:
        factor_id = factor.get("id", "").strip()
        factor_type = factor.get("factorType", "").strip().lower()
        provider = factor.get("provider", "").strip().lower()
        factor_url = factor.get("_links", {}).get("verify", {}).get("href")

        if len(factor_type) == 0 or len(provider) == 0 or len(factor_url) == 0:
            continue

        factors.append(
            {
                "id": factor_id,
                "type": factor_type,
                "provider": provider,
                "priority": mfa_priority(conf, factor_type, provider),
                "url": factor_url,
            }
        )

    dbg(conf.get("debug"), "factors", factors)

    if len(factors) == 0:
        err("no factors found")

    for f in sorted(factors, key=lambda x: x.get("priority", 0), reverse=True):
        ftype = f.get("type")

        if ftype == "token:software:totp":
            r = okta_mfa_totp(conf, s, f, state_token)
        elif ftype == "sms":
            r = okta_mfa_sms(conf, s, f, state_token)
        elif ftype == "push":
            r = okta_mfa_push(conf, s, f, state_token)
        else:
            r = None

        if r is not None:
            return r

    err("no factors processed")


def okta_mfa_push(conf, s, factor, state_token):
    provider = factor.get("provider", "")
    data = {"factorId": factor.get("id"), "stateToken": state_token}
    log(f"mfa {provider} push request")
    status = "MFA_CHALLENGE"

    while status == "MFA_CHALLENGE":
        _, j = send_req(conf, s, "push mfa", factor.get("url"), data, json=True)
        status = j.get("status", "").strip()
        dbg(conf.get("debug"), "status", status)

        if status == "MFA_CHALLENGE":
            time.sleep(1.5)

    return j.get("sessionToken", "").strip()


def okta_mfa_totp(conf, s, factor, state_token):
    provider = factor.get("provider", "")
    secret = conf.get(f"totp.{provider}", "") or ""
    code = None

    if len(secret) == 0:
        code = input(f"{provider} TOTP: ").strip()
    else:
        import pyotp

        totp = pyotp.TOTP(secret)
        code = totp.now()

    code = code or ""
    if len(code) == 0:
        return None
    data = {"factorId": factor.get("id"), "stateToken": state_token, "passCode": code}
    log(f"mfa {provider} totp request")
    _, j = send_req(conf, s, "totp mfa", factor.get("url"), data, json=True)
    return j.get("sessionToken", "").strip()


def okta_mfa_sms(conf, s, factor, state_token):
    provider = factor.get("provider", "")
    data = {"factorId": factor.get("id"), "stateToken": state_token}
    log(f"mfa {provider} sms request")
    _, j = send_req(conf, s, "sms mfa", factor.get("url"), data, json=True)
    code = input(f"{provider} SMS verification code: ").strip()

    if len(code) == 0:
        return None

    data["passCode"] = code
    _, j = send_req(conf, s, "sms mfa", factor.get("url"), data, json=True)

    return j.get("sessionToken", "").strip()


def okta_redirect(conf, s, session_token, redirect_url):
    rc = 0
    form_url, form_data = None, {}

    while True:
        if rc > 10:
            err("redirect rabbit hole is too deep...")

        rc += 1

        if redirect_url:
            data = {
                "checkAccountSetupComplete": "true",
                "report": "true",
                "token": session_token,
                "redirectUrl": redirect_url,
            }

            url = "{}/login/sessionCookieRedirect".format(conf.get("okta_url"))
            log("okta redirect request")
            h, c = send_req(conf, s, "redirect", url, data)
            redirect_url = get_redirect_url(conf, c, url)

            if redirect_url:
                form_url, form_data = None, {}
            else:
                xhtml = parse_html(c)
                form_url, form_data = parse_form(xhtml, url)

        elif form_url:
            log("okta redirect form request")
            h, c = send_req(conf, s, "redirect form", form_url, form_data)

        saml_username = h.get("saml-username", "").strip()
        prelogin_cookie = h.get("prelogin-cookie", "").strip()

        if saml_username and prelogin_cookie:
            saml_auth_status = h.get("saml-auth-status", "").strip()
            saml_slo = h.get("saml-slo", "").strip()
            dbg(conf.get("debug"), "saml prop", [saml_auth_status, saml_slo])

            return saml_username, prelogin_cookie


def paloalto_getconfig(conf, s, saml_username, prelogin_cookie):
    log("getconfig request")
    url = "{}/global-protect/getconfig.esp".format(conf.get("vpn_url"))
    data = {
        "user": saml_username,
        "passwd": "",
        "inputStr": "",
        "clientVer": "4100",
        "clientos": "Windows",
        "clientgpversion": "4.1.0.98",
        "computer": "DESKTOP",
        "os-version": "Microsoft Windows 10 Pro, 64-bit",
        # 'host-id': '00:11:22:33:44:55'
        "prelogin-cookie": prelogin_cookie,
        "ipv6-support": "yes",
    }

    _, c = send_req(conf, s, "getconfig", url, data)
    x = parse_xml(c)
    xtmp = x.find(".//portal-userauthcookie")

    if xtmp is None:
        err("did not find portal-userauthcookie")

    portal_userauthcookie = xtmp.text

    if len(portal_userauthcookie) == 0:
        err("empty portal_userauthcookie")

    return portal_userauthcookie


# Combined first half of okta_saml with second half of okta_redirect


def okta_saml_2(conf, s, saml_xml, again=False):
    log("okta saml request")
    url, data = parse_form(saml_xml)
    r = s.post(url, data=data)

    if r.status_code != 200:
        err(f"redirect request failed. {r}")

    dbg(conf.get("debug"), "redirect.response", r.status_code, r.text)
    xhtml = parse_html(r.text)

    url, data = parse_form(xhtml)
    log("okta redirect form request")
    r = s.post(url, data=data)

    if r.status_code != 200:
        err(f"redirect form request failed. {r}")

    dbg(conf.get("debug"), "form.response", r.status_code, r.text)
    saml_username = r.headers.get("saml-username", "").strip()

    if len(saml_username) == 0 and not again:
        err("saml-username empty")

    r.headers.get("saml-auth-status", "").strip()
    r.headers.get("saml-slo", "").strip()
    prelogin_cookie = r.headers.get("prelogin-cookie", "").strip()

    if len(prelogin_cookie) == 0:
        err("prelogin-cookie empty")

    return saml_username, prelogin_cookie


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="""
    This is an OpenConnect wrapper script that automates connecting to a
    PaloAlto Networks GlobalProtect VPN using Okta 2FA.
    """
    )
    parser.add_argument("conf_file", help="e.g. ~/.config/gp-okta.conf")
    parser.add_argument(
        "--gpg-decrypt",
        action="store_true",
        help="use gpg-home to decrypt gpg encrypted conf_file",
    )
    parser.add_argument("--gpg-home", default=os.path.expanduser("~/.gnupg"))
    parser.add_argument(
        "--verbose", default=False, action="store_true", help="enable verbose logging"
    )
    args = parser.parse_args()

    global verbose
    verbose = args.verbose

    assert os.path.exists(args.conf_file)
    assert not args.gpg_decrypt or os.path.isdir(args.gpg_home)

    config_contents = ""
    with open(args.conf_file) as f:
        config_contents = f.read()

    if args.gpg_decrypt:
        import gnupg

        gpg = gnupg.GPG(gnupghome=args.gpg_home)
        decrypted_contents = gpg.decrypt(config_contents)

        if not decrypted_contents.ok:
            print("failed to decrypt config file:")
            print(f"    status: {decrypted_contents.status}")
            print(f"     error: {decrypted_contents.stderr}")
            sys.exit(1)

        config_contents = decrypted_contents.data

    conf = load_conf(config_contents)

    s = requests.Session()
    s.headers["User-Agent"] = "PAN GlobalProtect"
    saml_xml = paloalto_prelogin_post(conf, s)

    redirect_url = okta_saml(conf, s, saml_xml)
    token = okta_auth(conf, s)
    log(f"sessionToken: {token}")

    saml_username, prelogin_cookie = okta_redirect(conf, s, token, redirect_url)
    log(f"saml-username: {saml_username}")
    log(f"prelogin-cookie: {prelogin_cookie}")

    userauthcookie = paloalto_getconfig(conf, s, saml_username, prelogin_cookie)
    log(f"portal-userauthcookie: {userauthcookie}")

    # Another dance?
    if conf.get("another_dance", "").lower() in ["1", "true"]:
        log("another dance phase 1")
        saml_xml = paloalto_prelogin_post(conf, s, again=True)
        log("another dance phase 2")
        saml_username, prelogin_cookie = okta_saml_2(conf, s, saml_xml, again=True)
        log("another dance phase 3")

    log(f"saml-username: {saml_username}")
    log(f"prelogin-cookie: {prelogin_cookie}")

    if userauthcookie == "empty" and prelogin_cookie != "empty":
        cookie_type = "gateway:prelogin-cookie"
        oc_cookie = prelogin_cookie
    else:
        cookie_type = "portal:portal-userauthcookie"
        oc_cookie = userauthcookie

    username = saml_username
    cmd = conf.get("openconnect_cmd") or "openconnect"
    cmd += " --protocol=gp -u '{0}'"
    cmd += " --usergroup {1}"
    cmd += " --passwd-on-stdin " + conf.get("openconnect_args", "") + " '{2}'"
    cmd = cmd.format(username, cookie_type, conf.get("vpn_url"))

    gw = (conf.get("gateway") or "").strip()

    bugs = ""
    if conf.get("bug.nl", "").lower() in ["1", "true"]:
        bugs += "\\n"
    if conf.get("bug.username", "").lower() in ["1", "true"]:
        bugs += "{}\\n".format(username.replace("\\", "\\\\"))
    if len(gw) > 0:
        pcmd = "printf '" + bugs + f"{oc_cookie}\\n{gw}'"
    else:
        pcmd = "printf '" + bugs + f"{oc_cookie}'"

    if conf.get("execute", "").lower() in ["1", "true"]:
        cmd = shlex.split(cmd)
        cmd = [os.path.expandvars(os.path.expanduser(x)) for x in cmd]
        pp = subprocess.Popen(shlex.split(pcmd), stdout=subprocess.PIPE)
        cp = subprocess.Popen(
            cmd, stdin=pp.stdout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        pp.stdout.close()
        # Do not abort on SIGINT. openconnect will perform proper exit & cleanup
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cp.communicate()

        if len(conf.get("post_connect_cmd", "").lower()) > 0:
            time.sleep(5)
            cmd = shlex.split(conf.get("post_connect_cmd"))
            cmd = [os.path.expandvars(os.path.expanduser(x)) for x in cmd]
            pp = subprocess.Popen(shlex.split(pcmd), stdout=subprocess.PIPE)
            cp = subprocess.Popen(
                cmd,
                stdin=pp.stdout,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            pp.stdout.close()
            # Do not abort on SIGINT. openconnect will perform proper exit & cleanup
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            cp.communicate()


if __name__ == "__main__":
    main()

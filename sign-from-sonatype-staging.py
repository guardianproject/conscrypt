#!/usr/bin/env python3

import os
import requests
import sys
import defusedxml.ElementTree as ElementTree
import xml.etree.ElementTree
from fdroidserver import mirror


class Options:
    verbose = True


mirror.options = Options


class MavenDownloader:

    baseurl = (
        "https://oss.sonatype.org/service/local/repositories/{repo}/content/{group}/"
    )

    root_dir = None
    root_url = None

    def __init__(self, root_dir, group, repo):
        if self.root_dir is None:
            self.root_dir = root_dir
        if self.root_url is None:
            self.root_url = self.baseurl.format(repo=repo, group=group)
            self.get(self.root_url)

    def get(self, url):
        print("get", url)
        urls = []
        r = requests.get(url)
        content = r.content.decode()
        try:
            root = ElementTree.fromstring(content)
        except xml.etree.ElementTree.ParseError as e:
            print(e)
            print(content)
        for child in root.find("data"):
            if child.tag == "content-item":
                resourceURI = child.find("resourceURI").text
                dldir = os.path.join(
                    self.root_dir, os.path.dirname(resourceURI[len(self.root_url) :])
                )
                os.makedirs(dldir, exist_ok=True)
                os.chdir(dldir)
                if child.find("leaf").text == "false":
                    self.get(resourceURI)
                elif resourceURI.split(".")[-1] not in (
                    "md5",
                    "sha1",
                    "sha256",
                    "sha512",  # skip the files that Maven Central generates
                ):
                    print(resourceURI)
                    urls.append(resourceURI)

        mirror._run_wget(dldir, urls)


def main():
    d = {
        "repo": "infoguardianproject-1072",
        "group": "info.guardianproject.conscrypt".replace(".", "/"),
    }
    dldir = os.path.join(os.getenv("HOME"), "Downloads", os.path.basename(__file__))
    print("Downloading", sys.argv[1], sys.argv[2], "into", dldir)
    md = MavenDownloader(dldir, sys.argv[1].replace(".", "/"), sys.argv[2])


if __name__ == "__main__":
    main()

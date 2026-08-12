# Third-Party Knowledge Notices

Blue Sec Hub source releases do not bundle the following upstream corpora. The installer downloads
the commits pinned in `sources.lock.json` into a rebuildable local cache. All synchronized content
is retrieval-only, untrusted, and has no instruction authority.

| Source | Project | License evidence |
|---|---|---|
| HackSkills | https://github.com/yaklang/hack-skills | Upstream license copied into the local cache; SHA256 pinned in `sources.lock.json` |
| Strix | https://github.com/usestrix/strix | Upstream license copied into the local cache; SHA256 pinned in `sources.lock.json` |
| Transilience | https://github.com/TransilienceAI/transilience | Upstream license copied into the local cache; SHA256 pinned in `sources.lock.json` |
| claude-bug-bounty | https://github.com/shuvonsec/claude-bug-bounty | Upstream license copied into the local cache; SHA256 pinned in `sources.lock.json` |
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | Upstream license copied into the local cache; SHA256 pinned in `sources.lock.json` |

The upstream projects retain their own copyright and license terms. Review the cached `licenses/`
directory before redistributing upstream content; the Blue Sec Hub archives redistribute none of it.

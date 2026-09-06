## Search engine crawler IP verification module for http_logviewer.
## Validates whether clients claiming to be search engine bots (Googlebot, Bingbot,
## Applebot, Baiduspider, YandexBot) originate from official published crawler IP ranges
## or are malicious script kiddies / scrapers spoofing bot User-Agents.

import std/strutils
import ../enrichment/bogon

type
  ## Verification result for a client IP claiming search engine crawler identity
  BotVerificationStatus* = enum
    BotIpVerified,      ## IP confirmed to belong to official crawler CIDR blocks
    BotIpPrivateOrTest, ## IP is private, loopback, or documentation (RFC 5737/1918), permitted for local testing
    BotIpSpoofed        ## IP is a public internet IP that does NOT belong to the claimed crawler

  ParsedIpv4Cidr = object
    netNum: uint32
    mask: uint32

func makeIpv4Cidr(ipStr: string, prefix: int): ParsedIpv4Cidr =
  var ipNum: uint32
  if parseIpv4ToUint32(ipStr, ipNum):
    let p = max(0, min(32, prefix))
    let mask = if p == 0: 0'u32
               elif p >= 32: 0xFFFFFFFF'u32
               else: not ((1'u32 shl uint32(32 - p)) - 1'u32)
    result = ParsedIpv4Cidr(netNum: ipNum and mask, mask: mask)

func isInCidr(ipNum: uint32, cidr: ParsedIpv4Cidr): bool {.inline.} =
  (ipNum and cidr.mask) == cidr.netNum

# Official Googlebot IPv4 ranges (published by Google)
# https://developers.google.com/search/docs/crawling-indexing/verifying-googlebot
# https://developers.google.com/search/apis/ipranges/googlebot.json
const GooglebotCidrs: array[14, ParsedIpv4Cidr] = [
  makeIpv4Cidr("66.249.64.0", 19),    # Primary Googlebot crawling range (66.249.64.0 - 66.249.95.255)
  makeIpv4Cidr("64.233.160.0", 19),
  makeIpv4Cidr("66.102.0.0", 20),
  makeIpv4Cidr("72.14.192.0", 18),
  makeIpv4Cidr("74.125.0.0", 16),
  makeIpv4Cidr("209.85.128.0", 17),
  makeIpv4Cidr("216.239.32.0", 19),
  makeIpv4Cidr("216.58.192.0", 19),
  makeIpv4Cidr("172.217.0.0", 16),
  makeIpv4Cidr("172.253.0.0", 16),
  makeIpv4Cidr("108.177.0.0", 17),
  makeIpv4Cidr("142.250.0.0", 15),
  makeIpv4Cidr("35.190.247.0", 24),
  makeIpv4Cidr("34.64.0.0", 10)
]

# Official Bingbot IPv4 ranges (published by Microsoft)
# https://www.bing.com/toolbox/bingbot.json
const BingbotCidrs: array[7, ParsedIpv4Cidr] = [
  makeIpv4Cidr("40.77.167.0", 24),
  makeIpv4Cidr("157.55.39.0", 24),
  makeIpv4Cidr("207.46.13.0", 24),
  makeIpv4Cidr("13.66.136.0", 21),
  makeIpv4Cidr("52.167.144.0", 20),
  makeIpv4Cidr("20.247.0.0", 16),
  makeIpv4Cidr("20.15.0.0", 16)
]

# Applebot IPv4 range (published by Apple: 17.0.0.0/8)
const ApplebotCidrs: array[1, ParsedIpv4Cidr] = [
  makeIpv4Cidr("17.0.0.0", 8)
]

# Baiduspider IPv4 ranges
const BaiduspiderCidrs: array[3, ParsedIpv4Cidr] = [
  makeIpv4Cidr("180.76.0.0", 16),
  makeIpv4Cidr("220.181.0.0", 16),
  makeIpv4Cidr("123.125.0.0", 16)
]

# YandexBot IPv4 ranges
const YandexBotCidrs: array[7, ParsedIpv4Cidr] = [
  makeIpv4Cidr("5.255.192.0", 18),
  makeIpv4Cidr("77.88.0.0", 18),
  makeIpv4Cidr("87.250.224.0", 19),
  makeIpv4Cidr("93.158.128.0", 18),
  makeIpv4Cidr("141.8.128.0", 18),
  makeIpv4Cidr("178.154.128.0", 18),
  makeIpv4Cidr("213.180.192.0", 19)
]

func isGooglebotIp*(ipNum: uint32): bool =
  for cidr in GooglebotCidrs:
    if isInCidr(ipNum, cidr): return true
  false

func isBingbotIp*(ipNum: uint32): bool =
  for cidr in BingbotCidrs:
    if isInCidr(ipNum, cidr): return true
  false

func isApplebotIp*(ipNum: uint32): bool =
  for cidr in ApplebotCidrs:
    if isInCidr(ipNum, cidr): return true
  false

func isBaiduspiderIp*(ipNum: uint32): bool =
  for cidr in BaiduspiderCidrs:
    if isInCidr(ipNum, cidr): return true
  false

func isYandexBotIp*(ipNum: uint32): bool =
  for cidr in YandexBotCidrs:
    if isInCidr(ipNum, cidr): return true
  false

func verifyCrawlerIp*(botName: string, clientIp: string): BotVerificationStatus =
  ## Validates if `clientIp` matches known published CIDRs for `botName` (e.g. "Googlebot", "Bingbot").
  ## Returns:
  ## - `BotIpVerified`: Client IP confirmed to belong to the crawler's published netblock.
  ## - `BotIpPrivateOrTest`: Local/private RFC 1918, loopback, or documentation (RFC 5737) IP.
  ## - `BotIpSpoofed`: Public internet IP claiming crawler identity without legitimate IP provenance.
  if clientIp.len == 0:
    return BotIpSpoofed

  # 1. Check if private, loopback, or documentation/test subnet
  let subnetKind = classifyIpSubnet(clientIp)
  if subnetKind in {SubnetPrivateRfc1918, SubnetLoopback, SubnetLinkLocal, SubnetUniqueLocalIpv6, SubnetDocumentation}:
    return BotIpPrivateOrTest

  # 2. IPv4 verification
  var ipNum: uint32
  if parseIpv4ToUint32(clientIp, ipNum):
    let lowerName = botName.toLowerAscii()
    if "google" in lowerName:
      if isGooglebotIp(ipNum): return BotIpVerified
    elif "bing" in lowerName or "msn" in lowerName:
      if isBingbotIp(ipNum): return BotIpVerified
    elif "apple" in lowerName:
      if isApplebotIp(ipNum): return BotIpVerified
    elif "baidu" in lowerName:
      if isBaiduspiderIp(ipNum): return BotIpVerified
    elif "yandex" in lowerName:
      if isYandexBotIp(ipNum): return BotIpVerified
    else:
      # For other crawlers without published CIDR checks, do not flag as spoofed
      return BotIpVerified

    return BotIpSpoofed

  # IPv6: Google / Bing IPv6 check (or fallback to verified if not IPv4)
  if clientIp.find(':') >= 0:
    let lowerName = botName.toLowerAscii()
    let lowerIp = clientIp.toLowerAscii()
    if "google" in lowerName:
      if lowerIp.startsWith("2001:4860:") or lowerIp.startsWith("2607:f8b0:"):
        return BotIpVerified
    elif "bing" in lowerName:
      if lowerIp.startsWith("2a01:111:2006:"):
        return BotIpVerified
    else:
      return BotIpVerified

    return BotIpSpoofed

  return BotIpSpoofed

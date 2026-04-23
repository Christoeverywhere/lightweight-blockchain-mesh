#include <ESP8266WiFi.h>
#include <WiFiUdp.h>

const char* ssid = "Meshdemo";
const char* password = "bingbong";

WiFiUDP udp;
const unsigned int localPort = 4210;

// =====================================
// CHANGE ONLY THESE 2 LINES PER BOARD
// =====================================
String NODE_ID = "C";
bool ENABLE_ATTACK = true; // true ONLY for Node C
// =====================================

String prevHash = "GENESIS";
unsigned long lastSendTime = 0;
unsigned long lastHelloTime = 0;
unsigned long lastAttackTime = 0;
int seqNo = 0;
int attackSeq = 0;

// dynamic peer discovery
String nodeA_IP = "";
String nodeB_IP = "";
String nodeC_IP = "";

// duplicate suppression
String seenMsgs[60];
int seenIndex = 0;

// sender blacklist and malicious counts
bool blacklistedA = false;
bool blacklistedB = false;
bool blacklistedC = false;

int badCountA = 0;
int badCountB = 0;
int badCountC = 0;

const int BLACKLIST_THRESHOLD = 2;

String simpleHash(String input) {
  uint32_t hash = 5381;
  for (int i = 0; i < input.length(); i++) {
    hash = ((hash << 5) + hash) + input[i];
  }
  char buf[11];
  sprintf(buf, "%08X", hash);
  return String(buf);
}

bool alreadySeen(String msgId) {
  for (int i = 0; i < 60; i++) {
    if (seenMsgs[i] == msgId) return true;
  }
  return false;
}

void rememberMsg(String msgId) {
  seenMsgs[seenIndex] = msgId;
  seenIndex = (seenIndex + 1) % 60;
}

bool isBlacklisted(String sender) {
  if (sender == "A") return blacklistedA;
  if (sender == "B") return blacklistedB;
  if (sender == "C") return blacklistedC;
  return false;
}

int getBadCount(String sender) {
  if (sender == "A") return badCountA;
  if (sender == "B") return badCountB;
  if (sender == "C") return badCountC;
  return 0;
}

void incrementBadCount(String sender) {
  if (sender == "A") badCountA++;
  else if (sender == "B") badCountB++;
  else if (sender == "C") badCountC++;
}

void blacklistSender(String sender) {
  if (sender == "A") blacklistedA = true;
  else if (sender == "B") blacklistedB = true;
  else if (sender == "C") blacklistedC = true;
}

void printSecurityStatus() {
  Serial.println();
  Serial.println("******** SECURITY STATUS ********");
  Serial.print(" A -> badCount: "); Serial.print(badCountA);
  Serial.print(" | blacklisted: "); Serial.println(blacklistedA ? "YES" : "NO");

  Serial.print(" B -> badCount: "); Serial.print(badCountB);
  Serial.print(" | blacklisted: "); Serial.println(blacklistedB ? "YES" : "NO");

  Serial.print(" C -> badCount: "); Serial.print(badCountC);
  Serial.print(" | blacklisted: "); Serial.println(blacklistedC ? "YES" : "NO");
  Serial.println("*********************************");
}

String getIPForNode(String node) {
  if (node == "A") return nodeA_IP;
  if (node == "B") return nodeB_IP;
  if (node == "C") return nodeC_IP;
  return "";
}

void setIPForNode(String node, String ip) {
  if (node == "A") nodeA_IP = ip;
  else if (node == "B") nodeB_IP = ip;
  else if (node == "C") nodeC_IP = ip;
}

void printPeerTable() {
  Serial.println();
  Serial.println("========= PEER TABLE =========");
  Serial.print(" Node A : "); Serial.println(nodeA_IP == "" ? "UNKNOWN" : nodeA_IP);
  Serial.print(" Node B : "); Serial.println(nodeB_IP == "" ? "UNKNOWN" : nodeB_IP);
  Serial.print(" Node C : "); Serial.println(nodeC_IP == "" ? "UNKNOWN" : nodeC_IP);
  Serial.println("==============================");
}

void sendToNode(String targetIP, String packet) {
  if (targetIP == "") return;

  IPAddress ip;
  if (ip.fromString(targetIP)) {
    udp.beginPacket(ip, localPort);
    udp.print(packet);
    udp.endPacket();

    Serial.print("   -> Sent to ");
    Serial.println(targetIP);
  }
}

void sendToAllKnownPeers(String packet, String excludeIP = "") {
  String myIP = WiFi.localIP().toString();

  if (nodeA_IP != "" && nodeA_IP != myIP && nodeA_IP != excludeIP) sendToNode(nodeA_IP, packet);
  if (nodeB_IP != "" && nodeB_IP != myIP && nodeB_IP != excludeIP) sendToNode(nodeB_IP, packet);
  if (nodeC_IP != "" && nodeC_IP != myIP && nodeC_IP != excludeIP) sendToNode(nodeC_IP, packet);
}

void broadcastHello() {
  String myIP = WiFi.localIP().toString();
  String helloPacket = "HELLO;" + NODE_ID + ";" + myIP;

  IPAddress broadcastIP(255, 255, 255, 255);
  udp.beginPacket(broadcastIP, localPort);
  udp.print(helloPacket);
  udp.endPacket();

  Serial.println();
  Serial.println("[DISCOVERY] Broadcasting HELLO...");
  Serial.print(" Node ID : "); Serial.println(NODE_ID);
  Serial.print(" IP      : "); Serial.println(myIP);
}

void handleHelloPacket(String packet, String remoteIP) {
  // HELLO;NodeID;IP
  int p1 = packet.indexOf(';');
  int p2 = packet.indexOf(';', p1 + 1);

  if (p1 < 0 || p2 < 0) return;

  String discoveredNode = packet.substring(p1 + 1, p2);
  String discoveredIP = packet.substring(p2 + 1);

  if (discoveredNode == NODE_ID) return;

  String oldIP = getIPForNode(discoveredNode);
  setIPForNode(discoveredNode, discoveredIP);

  if (oldIP != discoveredIP) {
    Serial.println();
    Serial.println("[DISCOVERY] Peer learned/updated");
    Serial.print(" Node    : "); Serial.println(discoveredNode);
    Serial.print(" IP      : "); Serial.println(discoveredIP);
    printPeerTable();
  }
}

bool allPeersKnown() {
  if (NODE_ID == "A") return (nodeB_IP != "" && nodeC_IP != "");
  if (NODE_ID == "B") return (nodeA_IP != "" && nodeC_IP != "");
  if (NODE_ID == "C") return (nodeA_IP != "" && nodeB_IP != "");
  return false;
}

void generateAndBroadcastValidBlock() {
  if (!allPeersKnown()) {
    Serial.println();
    Serial.println("[WAITING] Peer discovery incomplete. Skipping block generation.");
    printPeerTable();
    return;
  }

  seqNo++;

  String payload = "SMART_HOME_DATA_FROM_" + NODE_ID + "_SEQ_" + String(seqNo);
  int ttl = 2;

  String msgId = NODE_ID + "_" + String(seqNo);
  String blockContent = NODE_ID + "|" + String(seqNo) + "|" + payload + "|" + prevHash;
  String blockHash = simpleHash(blockContent);

  String packet = msgId + ";" +
                  NODE_ID + ";" +
                  String(seqNo) + ";" +
                  payload + ";" +
                  prevHash + ";" +
                  blockHash + ";" +
                  String(ttl);

  rememberMsg(msgId);

  Serial.println();
  Serial.println("========================================");
  Serial.println(" [LOCAL VALID BLOCK GENERATED]");
  Serial.println("========================================");
  Serial.print(" Node ID      : "); Serial.println(NODE_ID);
  Serial.print(" Message ID   : "); Serial.println(msgId);
  Serial.print(" Sequence No  : "); Serial.println(seqNo);
  Serial.print(" Payload      : "); Serial.println(payload);
  Serial.print(" Prev Hash    : "); Serial.println(prevHash);
  Serial.print(" Block Hash   : "); Serial.println(blockHash);
  Serial.print(" TTL          : "); Serial.println(ttl);
  Serial.println(" Broadcasting VALID block to discovered peers...");

  sendToAllKnownPeers(packet);

  Serial.println(" [Broadcast complete]");
  Serial.println("========================================");

  prevHash = blockHash;
}

void injectTamperedPacket() {
  if (!allPeersKnown()) {
    Serial.println();
    Serial.println("[WAITING] Peer discovery incomplete. Skipping attack simulation.");
    return;
  }

  attackSeq++;

  String fakeSender = NODE_ID;
  String fakeSeq = "ATTACK_" + String(attackSeq);
  String tamperedPayload = "MALICIOUS_TEMP=99C";
  String fakePrevHash = "FAKECHAIN";
  int ttl = 2;

  String wrongHash = "DEADBEEF";
  String msgId = NODE_ID + "_ATTACK_" + String(attackSeq);

  String packet = msgId + ";" +
                  fakeSender + ";" +
                  fakeSeq + ";" +
                  tamperedPayload + ";" +
                  fakePrevHash + ";" +
                  wrongHash + ";" +
                  String(ttl);

  rememberMsg(msgId);

  Serial.println();
  Serial.println("########################################");
  Serial.println(" [ATTACK SIMULATION: TAMPERED PACKET]");
  Serial.println("########################################");
  Serial.print(" Attacker Node : "); Serial.println(NODE_ID);
  Serial.print(" Message ID    : "); Serial.println(msgId);
  Serial.print(" Fake Seq      : "); Serial.println(fakeSeq);
  Serial.print(" Fake Payload  : "); Serial.println(tamperedPayload);
  Serial.print(" Fake PrevHash : "); Serial.println(fakePrevHash);
  Serial.print(" Wrong Hash    : "); Serial.println(wrongHash);
  Serial.println(" Injecting malicious packet into discovered mesh...");

  sendToAllKnownPeers(packet);

  Serial.println(" [Tampered packet sent]");
  Serial.println("########################################");
}

void handleBlockchainPacket(String packet, String remoteIP) {
  int p1 = packet.indexOf(';');
  int p2 = packet.indexOf(';', p1 + 1);
  int p3 = packet.indexOf(';', p2 + 1);
  int p4 = packet.indexOf(';', p3 + 1);
  int p5 = packet.indexOf(';', p4 + 1);
  int p6 = packet.indexOf(';', p5 + 1);

  if (p1 < 0 || p2 < 0 || p3 < 0 || p4 < 0 || p5 < 0 || p6 < 0) {
    Serial.println();
    Serial.println(" [INVALID PACKET FORMAT - DROPPED]");
    return;
  }

  String msgId     = packet.substring(0, p1);
  String sender    = packet.substring(p1 + 1, p2);
  String seqStr    = packet.substring(p2 + 1, p3);
  String payload   = packet.substring(p3 + 1, p4);
  String prevH     = packet.substring(p4 + 1, p5);
  String blockHash = packet.substring(p5 + 1, p6);
  int ttl          = packet.substring(p6 + 1).toInt();

  // learn sender IP dynamically from actual incoming packet
  if (sender == "A" || sender == "B" || sender == "C") {
    setIPForNode(sender, remoteIP);
  }

  if (isBlacklisted(sender)) {
    Serial.println();
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    Serial.println(" [BLACKLISTED NODE DETECTED]");
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    Serial.print(" Sender          : "); Serial.println(sender);
    Serial.print(" Message ID       : "); Serial.println(msgId);
    Serial.println(" Action           : PACKET IGNORED");
    Serial.println(" Reason           : Sender is blacklisted from mesh");
    Serial.println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    return;
  }

  if (alreadySeen(msgId)) {
    Serial.println();
    Serial.println("----------------------------------------");
    Serial.println(" [DUPLICATE BLOCK DETECTED - DROPPED]");
    Serial.print(" Message ID   : "); Serial.println(msgId);
    Serial.println("----------------------------------------");
    return;
  }

  rememberMsg(msgId);

  String recomputed = simpleHash(sender + "|" + seqStr + "|" + payload + "|" + prevH);

  Serial.println();
  Serial.println("========================================");
  Serial.println(" [BLOCK RECEIVED]");
  Serial.println("========================================");
  Serial.print(" Received From IP : "); Serial.println(remoteIP);
  Serial.print(" Original Sender  : "); Serial.println(sender);
  Serial.print(" Message ID       : "); Serial.println(msgId);
  Serial.print(" Sequence No      : "); Serial.println(seqStr);
  Serial.print(" Payload          : "); Serial.println(payload);
  Serial.print(" Prev Hash        : "); Serial.println(prevH);
  Serial.print(" Received Hash    : "); Serial.println(blockHash);
  Serial.print(" Recomputed Hash  : "); Serial.println(recomputed);
  Serial.print(" TTL              : "); Serial.println(ttl);

  if (recomputed == blockHash) {
    Serial.println(" Verification     : VALID");
  } else {
    Serial.println(" Verification     : INVALID");
    Serial.println(" [SECURITY ALERT] TAMPERING DETECTED!");
    incrementBadCount(sender);

    Serial.print(" Malicious Count  : ");
    Serial.println(getBadCount(sender));

    if (getBadCount(sender) >= BLACKLIST_THRESHOLD) {
      blacklistSender(sender);
      Serial.println(" [NODE BLACKLISTED]");
      Serial.print(" Sender           : ");
      Serial.println(sender);
      Serial.println(" Action           : LOGICALLY ISOLATED FROM MESH");
    } else {
      Serial.println(" Action           : PACKET DROPPED / WARNING ISSUED");
    }

    printSecurityStatus();
    Serial.println("========================================");
    return;
  }

  if (ttl > 0) {
    int newTTL = ttl - 1;

    String relayPacket = msgId + ";" +
                         sender + ";" +
                         seqStr + ";" +
                         payload + ";" +
                         prevH + ";" +
                         blockHash + ";" +
                         String(newTTL);

    Serial.print(" Action           : RELAYING TO PEERS (TTL -> ");
    Serial.print(newTTL);
    Serial.println(")");

    sendToAllKnownPeers(relayPacket, remoteIP);
  } else {
    Serial.println(" Action           : TTL EXPIRED - NO RELAY");
  }

  Serial.println("========================================");
}

void handleIncomingPacket() {
  int packetSize = udp.parsePacket();
  if (!packetSize) return;

  char incoming[512];
  int len = udp.read(incoming, 511);
  if (len > 0) incoming[len] = '\0';

  String packet = String(incoming);
  IPAddress remote = udp.remoteIP();
  String remoteIP = remote.toString();

  if (packet.startsWith("HELLO;")) {
    handleHelloPacket(packet, remoteIP);
    return;
  }

  handleBlockchainPacket(packet, remoteIP);
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("########################################################");
  Serial.println("# DYNAMIC BLOCKCHAIN MESH NODE + ATTACK ISOLATION (V4) #");
  Serial.println("########################################################");
  Serial.print("# Node ID             : "); Serial.println(NODE_ID);
  Serial.print("# Attack Mode         : "); Serial.println(ENABLE_ATTACK ? "ENABLED" : "DISABLED");
  Serial.print("# Blacklist Threshold : "); Serial.println(BLACKLIST_THRESHOLD);
  Serial.println("# Connecting to hotspot...");

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println();
  Serial.println("# Connected to hotspot");
  Serial.print("# Assigned IP         : "); Serial.println(WiFi.localIP());
  Serial.print("# MAC Address         : "); Serial.println(WiFi.macAddress());

  // store own IP in peer table too
  String myIP = WiFi.localIP().toString();
  setIPForNode(NODE_ID, myIP);

  udp.begin(localPort);
  Serial.print("# UDP Port            : ");
  Serial.println(localPort);

  printPeerTable();

  Serial.println("# Node Ready: DISCOVER + SEND + VERIFY + RELAY + BLACKLIST");
  Serial.println("########################################################");
}

void loop() {
  handleIncomingPacket();

  // discovery HELLO every 5 sec
  if (millis() - lastHelloTime > 5000) {
    lastHelloTime = millis();
    broadcastHello();
  }

  // valid block every 12 sec
  if (millis() - lastSendTime > 12000) {
    lastSendTime = millis();
    generateAndBroadcastValidBlock();
  }

  // tampered packet every 30 sec (only for attacker)
  if (ENABLE_ATTACK && (millis() - lastAttackTime > 30000)) {
    lastAttackTime = millis();
    injectTamperedPacket();
  }
}
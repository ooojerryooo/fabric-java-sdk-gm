package org.hyperledger.client;

import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.codec.binary.Hex;
import org.hyperledger.fabric.protos.ledger.rwset.kvrwset.KvRwset;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.springframework.util.ResourceUtils;

import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.BlockInfo.EnvelopeType.TRANSACTION_ENVELOPE;

public class FabricTools {

    private final String networkDomain;
    private final String networkId;

    public FabricTools(String networkDomain, String networkIdd) {
        this.networkDomain = networkDomain;
        this.networkId = networkIdd;
    }

    static String printableString(final String string) {
        int maxLogStringLength = 64;
        if (string == null || string.length() == 0) {
            return string;
        }
        String ret = string.replaceAll("[^\\p{Print}]", "?");
        ret = ret.substring(0, Math.min(ret.length(), maxLogStringLength)) + (ret.length() > maxLogStringLength ? "..." : "");
        return ret;
    }

    /**
     * @param name
     * @param mspId
     * @param keyFile
     * @param certFile
     * @return FabricUser
     * @description 获取任意类型用户
     * @author sunshjr
     **/
    public FabricUser getCommonUser(String name, String mspId, String signAlg, byte[] keyFile, byte[] certFile) throws Exception {
        return new FabricUser(name, mspId, signAlg, keyFile, certFile);
    }


    /**
     * @param user
     * @return org.hyperledger.fabric.sdk.HFClient
     * @description 初始化HyperLedgerFabric-Client
     * @author sunshjr
     **/
    public HFClient initHFClient(FabricUser user) throws Exception {
        HFClient hfClient = HFClient.createNewInstance();
        hfClient.setCryptoSuite(CryptoSuite.Factory.getCryptoSuite());
        hfClient.setUserContext(user);
        return hfClient;
    }

    /**
     * @param hfClient
     * @param domain
     * @param hostName
     * @param grpcUrl
     * @return org.hyperledger.fabric.sdk.Peer
     * @description 构建工作节点
     * @author sunshjr
     **/
    public Peer initializePeer(HFClient hfClient, String domain, String hostName, String grpcUrl) throws Exception {
        Properties peerProperties = new Properties();
        peerProperties.put("pemFile", Paths.get(this.getBlockConfigPath(),
                "/peerOrganizations/",
                domain, "/tlsca",
                format("/tlsca.%s-cert.pem", domain)).toString());
        peerProperties.put("hostnameOverride", hostName);
        peerProperties.put("sslProvider", "openSSL");
        peerProperties.put("negotiationType", "TLS");
        peerProperties.put("request-timeout", "300000");
        return hfClient.newPeer(hostName, grpcUrl, peerProperties);
    }

    /**
     * @param hfClient
     * @param hostName
     * @param grpcUrl
     * @param tlsca
     * @return org.hyperledger.fabric.sdk.Peer
     * @description 构建工作节点
     * @author sunshjr
     **/
    public Peer initializePeer(HFClient hfClient, String hostName, String grpcUrl, byte[] tlsca) throws Exception {
        Properties peerProperties = new Properties();
        peerProperties.put("pemBytes", tlsca);
        peerProperties.put("hostnameOverride", hostName);
        peerProperties.put("sslProvider", "openSSL");
        peerProperties.put("negotiationType", "TLS");
        peerProperties.put("request-timeout", "300000");
        return hfClient.newPeer(hostName, grpcUrl, peerProperties);
    }


    /**
     * @param hfClient
     * @param domain
     * @param hostName
     * @param grpcUrl
     * @return org.hyperledger.fabric.sdk.Orderer
     * @description 构建排序节点
     * @author sunshjr
     **/
    public Orderer initializeOrderer(HFClient hfClient, String domain, String hostName, String grpcUrl) throws Exception {
        Properties orderProperties = new Properties();
        orderProperties.put("pemFile", Paths.get(this.getBlockConfigPath(),
                "/ordererOrganizations/",
                domain, "/tlsca",
                format("/tlsca.%s-cert.pem", domain)).toString());
        orderProperties.put("hostnameOverride", hostName);
        orderProperties.put("sslProvider", "openSSL");
        orderProperties.put("negotiationType", "TLS");
        orderProperties.put("ordererWaitTimeMilliSecs", "300000");
        orderProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
        orderProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});
        orderProperties.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[]{true});
        return hfClient.newOrderer(hostName, grpcUrl, orderProperties);
    }

    public Orderer initializeOrderer(HFClient hfClient, String hostName, String grpcUrl, byte[] tlsca) throws Exception {
        Properties orderProperties = new Properties();
        orderProperties.put("pemBytes", tlsca);
        orderProperties.put("hostnameOverride", hostName);
        orderProperties.put("sslProvider", "openSSL");
        orderProperties.put("negotiationType", "TLS");
        orderProperties.put("ordererWaitTimeMilliSecs", "300000");
        orderProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
        orderProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});
        orderProperties.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[]{true});
        return hfClient.newOrderer(hostName, grpcUrl, orderProperties);
    }

    /**
     * @param hfClient
     * @param ccName
     * @param ccVersion
     * @param ccPath
     * @return org.hyperledger.fabric.sdk.InstallProposalRequest
     * @description 构建链码安装提案
     * @author sunshjr
     **/
    public InstallProposalRequest buildChaincodeProposal(HFClient hfClient, String ccName, String ccVersion, String ccPath) throws FileNotFoundException, InvalidArgumentException {
        ChaincodeID chaincodeID = this.buildChaincode(ccName, ccVersion, ccPath);
        InstallProposalRequest installProposalRequest = hfClient.newInstallProposalRequest();
        installProposalRequest.setChaincodeID(chaincodeID);
        installProposalRequest.setChaincodeSourceLocation(Paths.get(this.getClassPath(), "fabric-network/chaincode").toFile());
        installProposalRequest.setChaincodeVersion(ccVersion);
        installProposalRequest.setChaincodeLanguage(TransactionRequest.Type.GO_LANG);
        return installProposalRequest;
    }

    public ChaincodeID buildChaincode(String ccName, String ccVersion, String ccPath) {
        ChaincodeID chaincodeID = ChaincodeID.newBuilder()
                .setName(ccName)
                .setVersion(ccVersion)
                .setPath(ccPath).build();
        return chaincodeID;
    }

    /**
     * @param hfClient
     * @param channelname
     * @param ccName
     * @param fn
     * @param args
     * @return org.hyperledger.fabric.sdk.BlockEvent.TransactionEvent
     * @description 发送交易到区块链网络
     * @author sunshjr
     **/
    public BlockEvent.TransactionEvent send(HFClient hfClient, String channelname, String ccName, String fn, String... args) throws Exception {
        Channel channel = hfClient.getChannel(channelname);
        TransactionProposalRequest proposalRequest = hfClient.newTransactionProposalRequest();
        ChaincodeID ccId = ChaincodeID.newBuilder().setName(ccName).build();
        proposalRequest.setChaincodeID(ccId);
        proposalRequest.setFcn(fn);
        proposalRequest.setArgs(args);
        Collection<ProposalResponse> proposalResponse = channel.sendTransactionProposal(proposalRequest);
        return channel.sendTransaction(proposalResponse).get(30, TimeUnit.SECONDS);
    }

    /**
     * @param hfClient
     * @param channelname
     * @param ccName
     * @param fn
     * @param args
     * @return java.lang.String
     * @description 从区块链网络查询数据
     * @author sunshjr
     **/
    public String query(HFClient hfClient, String channelname, String ccName, String fn, String... args) throws Exception {
        Channel channel = hfClient.getChannel(channelname);
        QueryByChaincodeRequest request = hfClient.newQueryProposalRequest();
        ChaincodeID ccId = ChaincodeID.newBuilder().setName(ccName).build();
        request.setChaincodeID(ccId);
        request.setFcn(fn);
        request.setArgs(args);
        ProposalResponse[] responseArray = channel.queryByChaincode(request).toArray(new ProposalResponse[0]);
        return new String(responseArray[0].getChaincodeActionResponsePayload());
    }

    /**
     * @param
     * @return java.lang.String
     * @description 获取项目resources目录
     * @author sunshjr
     **/
    private String getBlockConfigPath() throws FileNotFoundException {
        String cfgPath = ResourceUtils.getURL("classpath:").getPath();
        String os = System.getProperty("os.name");
        if (os.toLowerCase().startsWith("win")) {
            cfgPath = ResourceUtils.getURL("classpath:").getPath().substring(1);
        }
        return Paths.get(cfgPath, format("fabric-network/channel/%s/%s/crypto-config", networkDomain, networkId)).toString();
    }

    private String getClassPath() throws FileNotFoundException {
        String cfgPath = ResourceUtils.getURL("classpath:").getPath().substring(1);
        return cfgPath;
    }

    public static List<Map<String, Object>> getRWSetFromBlock(BlockInfo blockInfo) throws Exception {
        List<Map<String, Object>> transactionList = new ArrayList<>();
        int txIndex = 0;
        for (BlockInfo.EnvelopeInfo envelopeInfo : blockInfo.getEnvelopeInfos()) {
            String id = envelopeInfo.getCreator().getId();
            String mspid = envelopeInfo.getCreator().getMspid();
            Date timestamp = envelopeInfo.getTimestamp();
            String transactionID = envelopeInfo.getTransactionID();
            boolean valid = envelopeInfo.isValid();
            byte validationCode = envelopeInfo.getValidationCode();
            int databytes = blockInfo.getBlock().getData().getData(txIndex).toByteArray().length;
            txIndex++;
            if (envelopeInfo.getType() == TRANSACTION_ENVELOPE) {
                BlockInfo.TransactionEnvelopeInfo transactionEnvelopeInfo = (BlockInfo.TransactionEnvelopeInfo) envelopeInfo;
                for (BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo transactionActionInfo : transactionEnvelopeInfo.getTransactionActionInfos()) {
                    Map<String, Object> transactionMap = new HashMap<>();
                    transactionMap.put("txType", "普通交易");
                    transactionMap.put("signature", Base64.getEncoder().encodeToString(transactionEnvelopeInfo.getSignature()));
                    transactionMap.put("transactionID", transactionID);
                    transactionMap.put("timestamp", timestamp.getTime());
                    transactionMap.put("isValid", valid);
                    transactionMap.put("MSPID", mspid);
                    transactionMap.put("usercert", id);
                    transactionMap.put("validationCode", validationCode);
                    transactionMap.put("databytes", databytes);
                    int chaincodeInputArgsCount = transactionActionInfo.getChaincodeInputArgsCount();
                    StringBuffer args = new StringBuffer();
                    for (int i = 0; i < chaincodeInputArgsCount; i++) {
                        args.append(new String(transactionActionInfo.getChaincodeInputArgs(i)));
                        args.append(",");
                    }
                    if (chaincodeInputArgsCount != 0) {
                        args.deleteCharAt(args.length() - 1);
                    }
                    transactionMap.put("args", args.toString());
                    transactionMap.put("status", transactionActionInfo.getResponseStatus());
                    transactionMap.put("endorsementsCount", transactionActionInfo.getEndorsementsCount());
                    String chaincodeIDName = transactionActionInfo.getChaincodeIDName();
                    transactionMap.put("chaincodeName", chaincodeIDName);
                    String chaincodeIDVersion = transactionActionInfo.getChaincodeIDVersion();
                    transactionMap.put("chaincodeVersion", chaincodeIDVersion);
                    String proposalResponse = new String(transactionActionInfo.getProposalResponsePayload(), "utf-8");
                    transactionMap.put("proposalResponse", proposalResponse);
                    TxReadWriteSetInfo rwsetInfo = transactionActionInfo.getTxReadWriteSet();
                    if (null != rwsetInfo) {
                        List<Map> rwList = new ArrayList<>();
                        for (TxReadWriteSetInfo.NsRwsetInfo nsRwsetInfo : rwsetInfo.getNsRwsetInfos()) {
                            Map<String, Object> rwMap = new HashMap<>();
                            Map<String, String> writeMap = new HashMap<>();
                            KvRwset.KVRWSet rws = nsRwsetInfo.getRwset();
                            StringBuffer readSet = new StringBuffer();
                            for (KvRwset.KVRead readList : rws.getReadsList()) {
                                String key = readList.getKey();
                                readSet.append(key);
                                readSet.append(",");
                            }
                            if (readSet.length() != 0) {
                                readSet.deleteCharAt(readSet.length() - 1);
                            }

                            rwMap.put("read", readSet);
                            for (KvRwset.KVWrite writeList : rws.getWritesList()) {
                                String valAsString = printableString(new String(writeList.getValue().toByteArray(), UTF_8));
                                writeList.getKey();
                                writeMap.put(writeList.getKey(), valAsString);
                            }
                            rwMap.put("write", writeMap);
                            rwList.add(rwMap);
                        }
                        transactionMap.put("RWSet", rwList);
                    }
                    transactionList.add(transactionMap);
                }
            } else {
                Map<String, Object> transactionMap = new HashMap<>();
                transactionMap.put("transactionID", transactionID);
                transactionMap.put("txType", "通道配置");
                transactionMap.put("timestamp", timestamp.getTime());
                transactionMap.put("isValid", valid);
                transactionMap.put("MSPID", mspid);
                transactionMap.put("usercert", id);
                transactionMap.put("validationCode", validationCode);
                transactionList.add(transactionMap);
            }
        }
        return transactionList;
    }

    public static List<Map<String, Object>> getRWSetFromBlock(BlockEvent blockInfo) throws InvalidProtocolBufferException, UnsupportedEncodingException {
        List<Map<String, Object>> transactionList = new ArrayList<>();
        int txIndex = 0;
        for (BlockInfo.EnvelopeInfo envelopeInfo : blockInfo.getEnvelopeInfos()) {
            String id = envelopeInfo.getCreator().getId();
            String mspid = envelopeInfo.getCreator().getMspid();
            Date timestamp = envelopeInfo.getTimestamp();
            String transactionID = envelopeInfo.getTransactionID();
            String nonce = Hex.encodeHexString(envelopeInfo.getNonce());
            boolean valid = envelopeInfo.isValid();
            byte validationCode = envelopeInfo.getValidationCode();
            int databytes = blockInfo.getBlock().getData().getData(txIndex).toByteArray().length;
            txIndex++;
            if (envelopeInfo.getType() == TRANSACTION_ENVELOPE) {
                BlockInfo.TransactionEnvelopeInfo transactionEnvelopeInfo = (BlockInfo.TransactionEnvelopeInfo) envelopeInfo;
                for (BlockInfo.TransactionEnvelopeInfo.TransactionActionInfo transactionActionInfo : transactionEnvelopeInfo.getTransactionActionInfos()) {
                    Map<String, Object> transactionMap = new HashMap<>();
                    transactionMap.put("transactionID", transactionID);
                    transactionMap.put("txType", "普通交易");
                    transactionMap.put("signature", Base64.getEncoder().encodeToString(transactionEnvelopeInfo.getSignature()));
                    transactionMap.put("timestamp", timestamp);
                    transactionMap.put("isValid", valid);
                    transactionMap.put("MSPID", mspid);
                    transactionMap.put("validationCode", validationCode);
                    transactionMap.put("databytes", databytes);
                    int chaincodeInputArgsCount = transactionActionInfo.getChaincodeInputArgsCount();
                    StringBuffer args = new StringBuffer();
                    for (int i = 0; i < chaincodeInputArgsCount; i++) {
                        args.append(new String(transactionActionInfo.getChaincodeInputArgs(i)));
                        args.append(",");
                    }
                    if (chaincodeInputArgsCount != 0) {
                        args.deleteCharAt(args.length() - 1);
                    }
                    transactionMap.put("args", args.toString());
                    transactionMap.put("status", transactionActionInfo.getResponseStatus());
                    transactionMap.put("proposalResponseStatus", transactionActionInfo.getProposalResponseStatus());
                    transactionMap.put("endorsementsCount", transactionActionInfo.getEndorsementsCount());
                    String chaincodeIDName = transactionActionInfo.getChaincodeIDName();
                    transactionMap.put("chaincodeName", chaincodeIDName);
                    String chaincodeIDVersion = transactionActionInfo.getChaincodeIDVersion();
                    transactionMap.put("chaincodeVersion", chaincodeIDVersion);

                    StringBuilder endorseInfo = new StringBuilder();
                    for (int i = 0; i < transactionActionInfo.getEndorsementsCount(); i++) {
                        BlockInfo.EndorserInfo eInfo = transactionActionInfo.getEndorsementInfo(i);
                        endorseInfo.append("[MSPID=\"");
                        endorseInfo.append(eInfo.getMspid());
                        endorseInfo.append("\",Signature=\"");
                        endorseInfo.append(Base64.getEncoder().encodeToString(eInfo.getSignature()));
                        endorseInfo.append("\",EndorsementCert=");
                        endorseInfo.append(eInfo.getId()).append("\"]").append(",");
                    }
                    if (transactionActionInfo.getEndorsementsCount() != 0) {
                        endorseInfo.deleteCharAt(endorseInfo.length() - 1);
                    }
                    System.out.println("endorsementStr.toString() = " + endorseInfo.toString());

                    String proposalResponse = new String(transactionActionInfo.getProposalResponsePayload(), UTF_8);
                    transactionMap.put("proposalResponse", proposalResponse);
                    TxReadWriteSetInfo rwsetInfo = transactionActionInfo.getTxReadWriteSet();
                    if (null != rwsetInfo) {
                        List<Map> rwList = new ArrayList<>();
                        for (TxReadWriteSetInfo.NsRwsetInfo nsRwsetInfo : rwsetInfo.getNsRwsetInfos()) {
                            Map<String, Object> rwMap = new HashMap<>();
                            Map<String, String> writeMap = new HashMap<>();
                            KvRwset.KVRWSet rws = nsRwsetInfo.getRwset();
                            StringBuffer readSet = new StringBuffer();
                            for (KvRwset.KVRead readList : rws.getReadsList()) {
                                String key = readList.getKey();
                                readSet.append(key);
                                readSet.append(",");
                            }
                            if (readSet.length() != 0) {
                                readSet.deleteCharAt(readSet.length() - 1);
                            }

                            rwMap.put("read", readSet);
                            for (KvRwset.KVWrite writeList : rws.getWritesList()) {
                                String valAsString = printableString(new String(writeList.getValue().toByteArray(), UTF_8));
                                writeList.getKey();
                                writeMap.put(writeList.getKey(), valAsString);
                            }
                            rwMap.put("write", writeMap);
                            rwList.add(rwMap);
                        }
                        transactionMap.put("RWSet", rwList);
                    }
                    transactionList.add(transactionMap);
                }
            } else {
                Map<String, Object> transactionMap = new HashMap<>();
                transactionMap.put("transactionID", nonce);
                transactionMap.put("timestamp", timestamp);
                transactionMap.put("txType", "配置交易");
                transactionMap.put("isValid", valid);
                transactionMap.put("MSPID", mspid);
                transactionMap.put("usercert", id);
                transactionMap.put("validationCode", validationCode);
                transactionMap.put("databytes", databytes);
                transactionList.add(transactionMap);
            }
        }
        return transactionList;
    }
}

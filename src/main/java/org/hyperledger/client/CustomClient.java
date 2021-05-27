package org.hyperledger.client;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.apache.commons.io.FileUtils;
import org.hyperledger.fabric.sdk.*;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.TransactionException;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * @ClassName CustomClient
 * @Description 创建定制化客户端
 * @Author 孙世江
 * @Data 2020/7/29 0029 上午 9:38
 * @Version 1.0
 **/
public class CustomClient {

    private HFClient hfClient;
    private FabricUser user;
    private Orderer orderer;
    private Channel channel;
    private HFConnectPojo hfConnectPojo;
    private ChaincodeID chaincodeID;


    public CustomClient(String networkPath,String cert, String priKey) throws TransactionException, InvalidArgumentException {
        parseNetworkJson2HFConnectPojo(networkPath, cert,priKey);
        initChannel();
        initOrderer();
        initPeer();
        channel.initialize();
    }

    public ChaincodeID buildChaincodeID() {
        chaincodeID = ChaincodeID.newBuilder().setName(hfConnectPojo.getCcName()).build();
        return chaincodeID;
    }

    private void parseNetworkJson2HFConnectPojo(String filePath, String certPath,String keyPath) {
        hfConnectPojo = new HFConnectPojo();
        try {
            String networkStr = FileUtils.readFileToString(Paths.get(filePath).toFile(), "utf-8");
            JSONObject jsonObject = JSON.parseObject(networkStr);
            JSONArray orders = jsonObject.getJSONArray("orderers");
            JSONObject orderer = orders.getJSONObject(0);
            hfConnectPojo.setOrdererHostName(orderer.getString("hostName"));
            hfConnectPojo.setOrdererGrpcUrl("grpcs://" + orderer.getString("IP") + ":" + orderer.getString("Port"));
            JSONArray peers = jsonObject.getJSONArray("peers");
            for (JSONObject peer : peers.toJavaList(JSONObject.class)) {
                HFConnectPojo.Peer peer1 = new HFConnectPojo.Peer();
                peer1.setHostName(peer.getString("hostName"));
                peer1.setGrpcUrl("grpcs://" + peer.getString("IP") + ":" + peer.getString("Port"));
                peer1.setTlsca(peer.getString("peerTlsca").getBytes());
                hfConnectPojo.addPeer(peer1);
            }
            hfConnectPojo.setOrderTlsca(jsonObject.getString("ordererTlsca").getBytes());
            String certStr = FileUtils.readFileToString(Paths.get(certPath).toFile(), "utf-8");
            hfConnectPojo.setCertBytes(certStr);
            String privKeyStr = FileUtils.readFileToString(Paths.get(keyPath).toFile(), "utf-8");
            hfConnectPojo.setKeyBytes(privKeyStr);
            hfConnectPojo.setChannelName(jsonObject.getString("channelName"));
            hfConnectPojo.setCcName(jsonObject.getString("ccName"));
            hfConnectPojo.setMspId(jsonObject.getString("mspId"));
            hfConnectPojo.setSignAlg(jsonObject.getString("signAlg"));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void initChannel() {
        initHFClient();
        try {
            channel = hfClient.newChannel(hfConnectPojo.getChannelName());
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void initPeer() {
        for (HFConnectPojo.Peer hfConnectPojoPeer : hfConnectPojo.getPeers()) {
            Properties peerProperties = new Properties();
            peerProperties.put("pemBytes", hfConnectPojoPeer.getTlsca());
            peerProperties.put("hostnameOverride", hfConnectPojoPeer.getHostName());
            peerProperties.put("sslProvider", "openSSL");
            peerProperties.put("negotiationType", "TLS");
            peerProperties.put("request-timeout", "300000");
            try {
                Peer peer = hfClient.newPeer(hfConnectPojoPeer.getHostName(), hfConnectPojoPeer.getGrpcUrl(), peerProperties);

                //自动发现
//                Channel.PeerOptions peerOptions = Channel.PeerOptions.createPeerOptions().setPeerRoles(EnumSet.of(Peer.PeerRole.SERVICE_DISCOVERY,
//                        Peer.PeerRole.LEDGER_QUERY, Peer.PeerRole.EVENT_SOURCE, Peer.PeerRole.CHAINCODE_QUERY));
//
//                channel.addPeer(peer, peerOptions);
                channel.addPeer(peer);
            } catch (InvalidArgumentException e) {
                e.printStackTrace();
            }
        }
    }

    private void initOrderer() {
        Properties orderProperties = new Properties();
        orderProperties.put("pemBytes", hfConnectPojo.getOrderTlsca());
        orderProperties.put("hostnameOverride", hfConnectPojo.getOrdererHostName());
        orderProperties.put("sslProvider", "openSSL");
        orderProperties.put("negotiationType", "TLS");
        orderProperties.put("ordererWaitTimeMilliSecs", "300000");
        orderProperties.put("grpc.NettyChannelBuilderOption.keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
        orderProperties.put("grpc.NettyChannelBuilderOption.keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});
        orderProperties.put("grpc.NettyChannelBuilderOption.keepAliveWithoutCalls", new Object[]{true});
        try {
            orderer = hfClient.newOrderer(hfConnectPojo.getOrdererHostName(), hfConnectPojo.getOrdererGrpcUrl(), orderProperties);
            channel.addOrderer(orderer);
        } catch (InvalidArgumentException e) {
            e.printStackTrace();
        }
    }


    private void initHFClient() {
        initUser();
        hfClient = HFClient.createNewInstance();
        try {
            hfClient.setCryptoSuite(FabricUser.getCryptoSuite(hfConnectPojo.getSignAlg()));
            hfClient.setUserContext(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initUser() {
        try {
            user = new FabricUser("User1",
                    hfConnectPojo.getMspId(),
                    hfConnectPojo.getSignAlg(),
                    hfConnectPojo.getKeyBytes().getBytes(),
                    hfConnectPojo.getCertBytes().getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public HFClient getHfClient() {
        return hfClient;
    }

    public Channel getChannel() {
        return channel;
    }

}

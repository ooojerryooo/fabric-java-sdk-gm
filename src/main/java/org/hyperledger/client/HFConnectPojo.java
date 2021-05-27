package org.hyperledger.client;

import java.util.ArrayList;
import java.util.List;

/**
 * @ClassName HFConnectPojo
 * @Author 孙世江
 * @Data 2020/7/29 0029 上午 11:16
 * @Version 1.0
 **/
public class HFConnectPojo {
    //组织MSPID
    private String mspId;
    //需要连接的channel名称
    private String channelName;
    //组织管理员私钥
    private String keyBytes;
    //组织管理员证书
    private String certBytes;
    //连接Orderer的serviceCode
    private String OrdererHostName;
    //连接Orderer的grpc地址
    private String ordererGrpcUrl;
    //排序服务的通讯证书
    private byte[] orderTlsca;
    //当前链码名称
    private String ccName;
    //Peer数组
    private List<Peer> peers = new ArrayList<>();
    //加密算法
    private String signAlg;

    static class Peer {
        //连接Peer的serviceCode
        private String hostName;
        //连接Peer的grpc地址
        private String grpcUrl;
        //组织的tls通讯证书
        private byte[] tlsca;

        public String getHostName() {
            return hostName;
        }

        public void setHostName(String hostName) {
            this.hostName = hostName;
        }

        public String getGrpcUrl() {
            return grpcUrl;
        }

        public void setGrpcUrl(String grpcUrl) {
            this.grpcUrl = grpcUrl;
        }

        public byte[] getTlsca() {
            return tlsca;
        }

        public void setTlsca(byte[] tlsca) {
            this.tlsca = tlsca;
        }
    }

    public String getOrdererHostName() {
        return OrdererHostName;
    }

    public void setOrdererHostName(String ordererHostName) {
        OrdererHostName = ordererHostName;
    }

    public String getOrdererGrpcUrl() {
        return ordererGrpcUrl;
    }

    public void setOrdererGrpcUrl(String ordererGrpcUrl) {
        this.ordererGrpcUrl = ordererGrpcUrl;
    }

    public byte[] getOrderTlsca() {
        return orderTlsca;
    }

    public void setOrderTlsca(byte[] orderTlsca) {
        this.orderTlsca = orderTlsca;
    }

    public void setMspId(String mspId) {
        this.mspId = mspId;
    }

    public void setChannelName(String channelName) {
        this.channelName = channelName;
    }

    public void setKeyBytes(String keyBytes) {
        this.keyBytes = keyBytes;
    }

    public void setCertBytes(String certBytes) {
        this.certBytes = certBytes;
    }

    public String getMspId() {
        return mspId;
    }

    public String getChannelName() {
        return channelName;
    }

    public String getKeyBytes() {
        return keyBytes;
    }

    public String getCertBytes() {
        return certBytes;
    }

    public String getCcName() {
        return ccName;
    }

    public void setCcName(String ccName) {
        this.ccName = ccName;
    }

    public List<Peer> getPeers() {
        return peers;
    }

    public void addPeer(Peer peer) {
        peers.add(peer);
    }

    public String getSignAlg() {
        return signAlg;
    }

    public void setSignAlg(String signAlg) {
        this.signAlg = signAlg;
    }
}

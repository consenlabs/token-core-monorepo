package im.imkey.imkeylibrary.common;


public class TransactionSignedResult {
  private String signedTx;
  private String txHash;
  private String wtxID;

  public String getWtxID() {
    return wtxID;
  }

  public void setWtxID(String wtxID) {
    this.wtxID = wtxID;
  }

  public String getSignedTx() {
    return signedTx;
  }

  public void setSignedTx(String signedTx) {
    this.signedTx = signedTx;
  }

  public String getTxHash() {
    return txHash;
  }

  public void setTxHash(String txHash) {
    this.txHash = txHash;
  }

  public TransactionSignedResult(String signedTx, String txHash) {
    this.signedTx = signedTx;
    this.txHash = txHash;
  }

  public TransactionSignedResult(String signedTx, String txHash, String wtxID) {
    this.signedTx = signedTx;
    this.txHash = txHash;
    this.wtxID = wtxID;
  }

  @Override
  public String toString() {
    return "TransactionSignedResult{" +
            "signedTx='" + signedTx + '\'' +
            ",\n\n txHash='" + txHash + '\'' +
            ",\n\n wtxID='" + wtxID + '\'' +
            '}';
  }
}

import java.util.ArrayList;
import java.util.List;

public class Transaction {

	String transactionId;
	int m;
	List<InputTransaction> inputList = new ArrayList<InputTransaction>();
	int n;
	List<OutputTransaction> outputList = new ArrayList<OutputTransaction>();
	String signature;
	boolean signaturePresent=false;

	public Transaction(String transactionId, int m, List<InputTransaction> inputList, int n,
			List<OutputTransaction> outputList) {
		super();
		this.transactionId = transactionId;
		this.m = m;
		this.inputList = inputList;
		this.n = n;
		this.outputList = outputList;
	}
	public Transaction() {
		// TODO Auto-generated constructor stub
		super();
	}
	public String getSignature() {
		return signature;
	}
	public void setSignature(String signature) {
		this.signature = signature;
	}
	public boolean isSignaturePresent() {
		return signaturePresent;
	}
	public void setSignaturePresent(boolean signaturePresent) {
		this.signaturePresent = signaturePresent;
	}
	public String getTransactionId() {
		return transactionId;
	}
	public void setTransactionId(String transactionId) {
		this.transactionId = transactionId;
	}
	public int getM() {
		return m;
	}
	public void setM(int m) {
		this.m = m;
	}
	public int getN() {
		return n;
	}
	public void setN(int n) {
		this.n = n;
	}
	public List<InputTransaction> getInputList() {
		return inputList;
	}
	public void setInputList(List<InputTransaction> inputList) {
		this.inputList = inputList;
	}
	public List<OutputTransaction> getOutputList() {
		return outputList;
	}
	public void setOutputList(List<OutputTransaction> outputList) {
		this.outputList = outputList;
	}

	public String toString(){
		String result;
		result = this.transactionId + "; " + this.m + "; ";
		if(this.m > 0) {
			if(this.inputList!=null) {
				for(InputTransaction in : this.inputList) {
					if(in.oldTransactionId!=null && in.indexOfOutputTx>-1) {
						result = result + "("+in.oldTransactionId+", " + in.indexOfOutputTx + ")";
					}
				}
			}
		}
		result+="; " +this.n+ "; ";

		for (OutputTransaction out : this.outputList) {
			result += "(" + out.name + ", " + out.amount + ")";
		}
		return result;
	}
}

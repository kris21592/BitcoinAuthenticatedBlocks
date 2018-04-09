import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Formatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

public class InteractiveMode {

	public static Map<String, Transaction> mapWithTransaction = new HashMap<String, Transaction>();
	public static Map<String, Integer> mapWithIndex = new HashMap<String, Integer>();
	public static List<Transaction> listOfTransactions = new ArrayList<Transaction>();
	public static Map<String, Integer> balanceMap = new HashMap<String, Integer>();
	public static Map<String, Integer> changeMap = new HashMap<String, Integer>();
	public static Map<String, Transaction> verifiedTransactionMap = new HashMap<String, Transaction>();
	public static Map<String, String> publickeyMap = new HashMap<String, String>();
	public static List<Block> outputBlockchain = new LinkedList<Block>();
	public static Map<String, Integer> finalBalanceMap = new HashMap<String, Integer>();
	public static Map<String, Integer> finalChangeMap = new HashMap<String, Integer>();
	public static List<Transaction> finalList = new ArrayList<Transaction>();

	Scanner sc = new Scanner(System.in);
	Boolean interactiveFlag = false;
	static Boolean verboseFlag = false;
	Boolean isGenesis = false;
	Boolean checkTransaction = false;
	int tempCtr=0;
	int mapIndex = 0;
	static String correctSha1;
	static Boolean fileRead = false;

	public void displayInteractiveMenu() throws Exception{
		System.out.println("[F]ile");
		System.out.println("[T]ransaction");
		System.out.println("[P]rint");
		System.out.println("[H]elp");
		System.out.println("[D]ump");
		System.out.println("[W]ipe");
		System.out.println("[I]nteractive");
		System.out.println("[V]erbose");
		System.out.println("[B]alance");
		System.out.println("[O]utput Transaction Block");
		System.out.println("[C]heck Transaction Signature");
		System.out.println("[R]ead Key File");
		System.out.println("[E]xit");

		while(true){
			System.out.println("\nSelect a command: ");
			String input = sc.next().toLowerCase();
			switchMethods(input);
		}
	}

	public void switchMethods(String input) throws Exception
	{

		switch(input){

			case "f":
			case "file":
			{
				if(interactiveFlag)
					System.out.println("Supply Filename: ");
				String filename = sc.next();
				BufferedReader br = null;
				try {
					br = new BufferedReader(new FileReader(filename));
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					System.err.println("Error: file "+filename+" cannot be opened for reading");
					break;
				}

				String line = null, nextLine = null, digSignature = null;
				//boolean isTransaction = false;
				try {
					line = br.readLine();
					nextLine = line;
				} catch (IOException e) {
					// TODO Auto-generated catch block
					System.err.println("Error: While reading "+filename+" file");
					break;
				}

				while (line != null && nextLine !=null) {
					line = nextLine;
					digSignature = br.readLine();
					if(isTransaction(digSignature)) {
						nextLine = digSignature;
						digSignature = null;
					}
					else {
						nextLine = br.readLine();
					}
					Transaction t = parseTransaction(line, digSignature);
					updateLedger(t);
				}
				br.close();
			}
			break;

			case "t":
			case "transaction":
			{
				if(interactiveFlag)
					System.out.println("Supply Transaction: ");
				BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
				String transaction = br.readLine();
				System.out.println(transaction);
				//toupdate
				//Transaction t=parseTransaction(transaction);
				//updateLedger(t);
			}
			break;

			case "p":
			case "print":
			{
				for(Transaction t: finalList){
					System.out.println(t.toString());
				}
				//String p = getTransactionAsString();
				//System.out.println(p);
			}
			break;

			case "h":
			case "help":
			{
				help();
			}
			break;

			case "d":
			case "dump":
			{
				BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
				String outputFileName = br.readLine().trim();
				for(Transaction t: finalList)
					write(t.toString()+System.lineSeparator(), outputFileName);
			}
			break;

			case "w":
			case "wipe":
			{
				if(outputBlockchain.isEmpty()){
					wipeLedger();
				}
				else{
					for(int i = listOfTransactions.size()-1;i>0;--i){
						for(Transaction t2: finalList){
							if(listOfTransactions.get(i)==t2){
								mapWithIndex.remove(listOfTransactions.get(i));
								mapWithTransaction.remove(listOfTransactions.get(i));
								listOfTransactions.remove(listOfTransactions.get(i));
							}
						}
					}
				finalList.clear();
				}
				//wipeLedger();
				if(verboseFlag)
					System.out.println("Ledger has been wiped");
			}
			break;

			case "i":
			case "interactive":
			{
				if(interactiveFlag==false){
					interactiveFlag=true;
					displayInteractiveMenu();
				}
				else{
					interactiveFlag=false;
					nonInteractive();
				}
			}
			break;

			case "v":
			case "verbose":
			{
				verboseFlag = !verboseFlag;
				if(verboseFlag){
					System.out.println("Now in Verbose Mode.");
				}
			}
			break;

			case "b":
			case "balance":
			{
				if(interactiveFlag)
					System.out.println("Enter name: ");
				String n = sc.next();
				if(finalBalanceMap.containsKey(n)){
					System.out.println(n+" has "+finalBalanceMap.get(n));
				}
				else
					System.err.println("Person does not exist!");
			}
			break;

			case "e":
			case "exit":
			{
				if(verboseFlag)
					System.out.println("Exiting.. ");
				System.exit(0);
			}
			break;


			case "r":
			{
				BufferedReader bread = new BufferedReader(new InputStreamReader(System.in));
				System.out.println("Supply Name and KeyFile Name: ");
				String inputStr[] = bread.readLine().split("\\s+");

				BufferedReader br = null;
				String key = "";
				String line = null;
				try{
					try {
						br = new BufferedReader(new FileReader(inputStr[1]));
					} catch (FileNotFoundException e) {
						// TODO Auto-generated catch block
						System.err.println("Error: file "+inputStr[1]+" cannot be opened for reading");
						break;
					}
				} catch(ArrayIndexOutOfBoundsException exception) {
					System.err.println("Please enter both name and filename separated by space." + "\n" + exception);
					break;
					}
				line = br.readLine();
				while(line!=null){
					key = key+line.replaceAll("-----BEGIN PUBLIC KEY-----", "").replaceAll("-----END PUBLIC KEY-----", "").replaceAll("\n", "").replaceAll("\r", "");
					line = br.readLine();
				}

				if(publickeyMap.containsKey(inputStr[0])){
					System.out.println("Key file being overwritten");
					publickeyMap.put(inputStr[0], key);
				}
				else
					publickeyMap.put(inputStr[0], key);

				System.out.println("Public key " + inputStr[0] + " " + inputStr[1] + " read");
			}
			break;

			case "c":
			{
				System.out.println("Enter transaction id: ");
				String transactionId = sc.next();
				String signature = null;
				boolean verified = false;
				if(mapWithTransaction.containsKey(transactionId))
				{
					Transaction t = mapWithTransaction.get(transactionId);
					if(t.m==0){
						if(t.signaturePresent){
							if(publickeyMap.containsKey(t.outputList.get(0).name)){
								verified = verify(t.outputList.get(0).name.toLowerCase()+"_public.pem",t.signature,t.toString().substring(10));
								if(verified)
									System.out.println("OK");
								else
									System.out.println("Bad");
							}
							else
								System.out.println("Error: Key not present for "+t.outputList.get(0).name);
						}
						else
							System.out.println("Bad");
					}
					else{
						Transaction prev_t = mapWithTransaction.get(t.inputList.get(0).oldTransactionId);
						int ind = t.inputList.get(0).indexOfOutputTx;
						String name = prev_t.outputList.get(ind).name;
						//System.out.println("name: "+ name + " Signature present? "+ t.signaturePresent);
						if(t.signaturePresent){
							if(publickeyMap.containsKey(name)){
								verified = verify(name.toLowerCase()+"_public.pem",t.signature,t.toString().substring(10));
								if(verified){
									System.out.println("OK");
								}
								else
									System.out.println("Bad");
							}
							else
								System.out.println("Bad");
						}
						else
							System.out.println("Error: Key not present for "+name);
					}
				}
				else
				{
					System.out.println("Invalid Transaction ID: Not present in Ledger.");
				}
			}
			break;

			case "o":
			{
				Boolean validTransaction = false;
				Boolean blockAdded = false;
				Block tempList = new Block();
				for(Transaction t: listOfTransactions){
					if(t.m==0){
						System.out.println("Inside : GENESIS! ");
						if(outputBlockchain.isEmpty()){
							if(t.signaturePresent && verify(t.outputList.get(0).name.toLowerCase()+"_public.pem",t.signature,t.toString().substring(10))){
									validTransaction = true;

									tempList.transactions.add(t);

									//System.out.println("TRANSACTION ADDED");
							}
							else{
								validTransaction = false;
								//System.out.println("Signature not valid");
							}

						}
						else{
							System.out.println("Genesis already in blockchain");
						}
					}
					else{
						if(!tempList.transactions.isEmpty()){
							if(outputBlockchain.isEmpty() && tempList.transactions.get(0).m==0){
								System.out.println("INSIDE OTHER TRANSACTIONS");
								Transaction prev_t = mapWithTransaction.get(t.inputList.get(0).oldTransactionId);
								int ind = t.inputList.get(0).indexOfOutputTx;
								String name = prev_t.outputList.get(ind).name;
								if(t.signaturePresent && verify(name.toLowerCase()+"_public.pem",t.signature,t.toString().substring(10))){

										tempList.transactions.add(t);

								}
								else{
									validTransaction = false;
									System.out.println("Signature not valid");
								}
							}
							else{
								for(Block block: outputBlockchain){
									//for(Transaction tran : block.transactions){
									System.out.println("INSIDE OTHER TRANSACTIONS");
										Transaction prev_t = mapWithTransaction.get(t.inputList.get(0).oldTransactionId);
										int ind = t.inputList.get(0).indexOfOutputTx;
										String name = prev_t.outputList.get(ind).name;
										System.out.println("NAME: "+name);
										if(t.signaturePresent && verify(name.toLowerCase()+"_public.pem",t.signature,t.toString().substring(10))){
											if(block.transactions.contains(t)){
												validTransaction = false;
												System.out.println("Transaction already in a previous block");
											}
											else{
												tempList.transactions.add(t);

											}
										}
										else{
											validTransaction = false;
											System.out.println("Signature not valid");
										}
									}
								}
							}
						else
							if(validTransaction==false)
								System.out.println(t.transactionId+": Genesis transaction was not added. Cannot add this transaction.");
					}
				}

				if(!tempList.transactions.isEmpty()){
					blockAdded = true;
					outputBlockchain.add(tempList);
					for(Transaction t: tempList.transactions)
						finalList.remove(t);
					for(Transaction trans : outputBlockchain.get(outputBlockchain.size()-1).transactions){
						if(trans.m == 0){
							for(OutputTransaction o: trans.outputList)
							{
								finalBalanceMap.put(o.name, o.amount);
								finalChangeMap.put(o.name, o.amount);
								//System.out.println("Balance for: "+o.name+" is: "+o.amount);
							}
						}
						else{
							updateBalance(trans);
							for(OutputTransaction o: trans.outputList)
							{
								if(finalChangeMap.containsKey(o.name))
									finalBalanceMap.put(o.name,finalChangeMap.get(o.name));
								else
									finalBalanceMap.put(o.name, o.amount);
							}
						}
					}
				}
				else
					System.out.println("No transactions added to block.");

				if(blockAdded == true){
					if(!outputBlockchain.isEmpty()){
						int indexOfBlockchain = outputBlockchain.size()-1;
						int sizeOfCurrentBlock = outputBlockchain.get(indexOfBlockchain).getTransactions().size();
						List<Transaction> tList = outputBlockchain.get(indexOfBlockchain).getTransactions();
						System.out.println(sizeOfCurrentBlock);
						for(Transaction tr: tList){
							System.out.println(tr.toString()+System.lineSeparator()+tr.signature);
						}
					}
					else
						System.out.println("Blockchain is empty");
				}
			}
			break;
			default:
			{
				System.out.println("Incorrect option. Please check help for command summary");
			}
		}
	}

	public static boolean verify(String pubFile, String signature, String data) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, IOException, SignatureException
	{
		//System.out.println("Inside verify: sig "+signature+" \nfile: "+pubFile+" \ndata " + data);
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(getPublic(pubFile));
		sig.update(data.getBytes());
		if(sig.verify(Base64.getDecoder().decode(signature)))
			return true;
		else
			return false;
	}

	public static PublicKey getPublic(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		String publicKeyContent = new String(Files.readAllBytes(Paths.get(filename)));
		publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
		KeyFactory kf = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyContent));
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
        return pubKey;
	}

	private boolean isTransaction(String signature) {
		return signature!=null && signature.length()>8 && (signature.charAt(8)==';');
	}

	private void updateBalance(Transaction t){
		finalChangeMap.clear();
		String oldTxId;
		int indexOfOldTx;
		Transaction old = null;
		int inputAmt;
		String inputName = null;
		int inputSum = 0;
		int outputSum = 0;
		int change;
		for(int index = 0;index<t.m;index++){
			oldTxId = t.inputList.get(index).oldTransactionId;
			System.out.println("Old t id: "+oldTxId);
			indexOfOldTx = mapWithIndex.get(oldTxId);
			old = listOfTransactions.get(indexOfOldTx);
			System.out.println("Blockchain size: "+outputBlockchain.size());

			System.out.println("Old trans id: "+old.transactionId);
			inputAmt = old.outputList.get(t.inputList.get(index).indexOfOutputTx).amount;
			inputName = old.outputList.get(t.inputList.get(index).indexOfOutputTx).name;
			if(finalBalanceMap.get(inputName) >= inputAmt)
			{
				inputSum+=inputAmt;
				//System.out.println("input sum: "+ inputSum + " old input amt: "+inputAmt);

				change = finalBalanceMap.get(inputName) - inputSum;
				finalChangeMap.put(inputName, change);
				//System.out.println("Change: "+change);
			}
			else{
				System.err.println(t.transactionId+": Error! account does not have enough Balance! ");
			}
		}
			for(int index = 0;index<t.n;index++){
				//System.out.println("here in N");
				if(!(finalChangeMap.containsKey(t.outputList.get(index).name)))
				{
					if(!t.outputList.get(index).name.equals(inputName)){
						//System.out.println("OUTPUT NAME: "+t.outputList.get(index).name+" INPUT NAME: "+inputName+" Balance of output NAME: "+ balanceMap.get(t.outputList.get(index).name)+" CURR AMT: "+t.outputList.get(index).amount);
						if(finalBalanceMap.containsKey(t.outputList.get(index).name))
							finalChangeMap.put(t.outputList.get(index).name, t.outputList.get(index).amount+finalBalanceMap.get(t.outputList.get(index).name));
					}
					else
						finalChangeMap.put(t.outputList.get(index).name, t.outputList.get(index).amount);
				}
				else
				{
					finalChangeMap.put(t.outputList.get(index).name, finalChangeMap.get(t.outputList.get(index).name)+t.outputList.get(index).amount);
				}
				outputSum+=t.outputList.get(index).amount;
			}

	}
	private void wipeLedger() {
		// TODO Auto-generated method stub
		mapWithTransaction.clear();
		mapWithIndex.clear();
		listOfTransactions.clear();
		finalList.clear();
		balanceMap.clear();
		changeMap.clear();
		resetFlags();
	}

	private void resetFlags() {
		// TODO Auto-generated method stub
		interactiveFlag = false;
		verboseFlag = false;
		isGenesis = false;
		checkTransaction = false;
		tempCtr=0;
		mapIndex = 0;
	}

	private void help() {
		// TODO Auto-generated method stub
		System.out.println("List of commands: \n");
		System.out.println("1. File\nCommand[F/f/file]\nInput Required[input filename]\nWill read in transactions from a file and add it to the ledger if successfully validated.\n");
		System.out.println("2. Transaction\nCommand[T/t/transaction]\nInput Required[transaction in the format shown below]\nWill take in the transaction given as input and validate it against the ledger and add if successfully validated.\n");
		System.out.println("Format of Transactions:\n<TransID>; M; (<TransID>, <vout>)^M; N; (<AcctID>, <amount>)^N\nItems in angle brackets are parameters, M and N are whole numbers, and caret M (or N) indicates M (or N) repetitions of the parenthesized pairs.");
		System.out.println("\nExample Transaction:\n4787df35; 1; (f2cea539, 0); 3; (Bob, 150)(Alice, 845)(Gopesh, 5)\n");
		System.out.println("3. Print\nCommands[P/p/print], Prints the ledger on the screen\n");
		System.out.println("4. Help\nCommands[H/h/help]\nOpens summary of commands.\n");
		System.out.println("5. Dump\nCommands[D/d/dump]\nInput Required[output filename]\nDumps the contents of the ledger into the output file.\n");
		System.out.println("6. Wipe\nCommands[W/w/wipe]\nWill wipe the ledger clean.\n");
		System.out.println("7. Interactive\nCommands[I/i/interactive]\nToggle between interactive and non interactive modes.\n");
		System.out.println("8. Verbose\nCommands[V/v/verbose]\nToggle between verbose and non verbose modes.\n");
		System.out.println("9. Balance\nCommands[B/b/balance], Input Required[account id]\nDisplay balance of the account id entered.\n");
		System.out.println("10. Exit\nCommands[E/e/exit]\nExit the program");
	}

	public String getTransactionAsString(){
		StringBuilder sb = new StringBuilder();
		for(Transaction t: listOfTransactions){
			sb.append(t.toString()).append(System.lineSeparator());
		}
		return sb.toString();
	}

	void nonInteractive() throws Exception {
		// TODO Auto-generated method stub
		while(true){
			String s = sc.next().toLowerCase();
			switchMethods(s);}
	}

	public void updateLedger(Transaction t) throws Exception{
		if(t.m==0){
			isGenesis = true;
			String name = t.outputList.get(0).name;

			mapWithTransaction.put(t.transactionId, t);
			mapWithIndex.put(t.transactionId, mapIndex);
			listOfTransactions.add(t);
			finalList.add(t);
			mapIndex++;
			for(OutputTransaction o: t.outputList)
			{
				balanceMap.put(o.name, o.amount);
				changeMap.put(o.name, o.amount);
				//System.out.println("Balance for: "+o.name+" is: "+o.amount);
			}
			System.out.println(t.transactionId+": good");
		}
		else
		{
			checkTransaction = validateTransaction(t);
			if(!correctSha1.equals(t.transactionId)){
				t.transactionId=correctSha1;
			}
			if(checkTransaction == true){
				listOfTransactions.add(t);
				finalList.add(t);
				System.out.println(t.transactionId+": good");
				if(verboseFlag)
					System.out.println("Adding transaction to ledger.. ");

				mapWithTransaction.put(t.transactionId, t);
				mapWithIndex.put(t.transactionId, mapIndex);
				mapIndex++;

				for(OutputTransaction o: t.outputList)
				{
					if(changeMap.containsKey(o.name))
						balanceMap.put(o.name,changeMap.get(o.name));
					else
						balanceMap.put(o.name, o.amount);
				}
			}
			else{
				System.out.println(t.transactionId+": bad");
				//System.out.println("Invalid Transaction! ");
			}
		}
	}

	public Transaction parseTransaction(String line, String digSignature){
		String trans[] = null;
		String t1[] = null;
		String t2[] = null;
		String t3[] = null;
		String t4[] = null;
		String name, txId, oldTxId;
		int m = 0,n,opTx,ipTx,amt;
		while(line!=null){
			Transaction transaction = new Transaction();
			InputTransaction in = new InputTransaction();
			OutputTransaction out = new OutputTransaction();
			List<InputTransaction> l1 = new ArrayList<InputTransaction>();
			List<OutputTransaction> l2 = new ArrayList<OutputTransaction>();
			line=line.replaceAll("\\s", "");
			if(line.charAt(8) == ';'){
				trans = line.split(";");
				m = Integer.parseInt(trans[1]);
				if(m==0){
					if(isGenesis == true){
						System.err.println("Error! Genesis transaction already exists!");
					}
					else{
						Transaction t = new Transaction();
						txId = trans[0];
						t.setTransactionId(txId);
						n = Integer.parseInt(trans[3]);
						t.setM(m);
						t.setN(n);
						t1 = trans[2].split("\\)");
						t3 = trans[4].split("\\)");

						for(int index = 0; index<t3.length; index++){
							out = new OutputTransaction();
							t4 =t3[index].split(",");
							name = t4[0].replaceAll("\\(", "");
							out.setName(name);
							amt = Integer.parseInt(t4[1]);
							out.setAmount(amt);
							l2.add(out);
						}
						t.setOutputList(l2);
						if(digSignature == null){
							t.setSignaturePresent(false);
							t.setSignature(null);
							//System.out.println(t.transactionId+": Signature is not present.");
						}
						else{
							t.setSignaturePresent(true);
							t.setSignature(digSignature);
						}
						//System.out.println("Object signature: "+ t.signature);
						return t;
					}
				}
				else{
						if(isGenesis == false)
						{
							System.err.println("Error: Genesis transaction required. ");
						}
						else
						{
							Transaction t = new Transaction();
							//Parsing from second line
							txId = trans[0];
							t.setTransactionId(txId);
							t.setM(m);
							t1 = trans[2].split("\\)");
							for(int index = 0; index<t1.length; index++){
								in = new InputTransaction();
								t2 = t1[index].split(",");
								oldTxId = t2[0].replaceAll("\\(", "");
								in.setOldTransactionId(oldTxId);
								opTx = Integer.parseInt(t2[1]);
								in.setIndexOfOutputTx(opTx);
								l1.add(in);
							}
							t.setInputList(l1);
							n = Integer.parseInt(trans[3]);
							t.setN(n);
							t3 = trans[4].split("\\)");
							for(int index = 0; index<t3.length; index++){
								out = new OutputTransaction();
								t4 =t3[index].split(",");
								name = t4[0].replaceAll("\\(", "");
								out.setName(name);
								amt = Integer.parseInt(t4[1]);
								out.setAmount(amt);
								l2.add(out);
							}
							t.outputList = l2;
							//System.out.println("Sig length: "+digSignature.length());
							if(digSignature == null){
								t.setSignaturePresent(false);
								t.setSignature(null);
								//System.out.println("Signature is not present.");
							}
							else{
								t.setSignaturePresent(true);
								t.setSignature(digSignature);
							}
							//System.out.println("Object signature: "+ t.signature);
							return t;
						}
					}
				}
			else
			{
				System.err.println("Error: Format of the transaction is incorrect!");
				break;
			}
			}
		return null;
	}

	public static boolean validateTransaction(Transaction t) throws Exception{
		changeMap.clear();
		int m = t.getM();
		int n = t.getN();
		String inputName = null;
		int inputSum=0;
		int outputSum=0;
		int inputAmt;
		int change=0;
		String txId = t.getTransactionId();
		Transaction old = null;
		int indexOfOldTx;
		String keyFileName;
		String privateKey;
		List<String> tempSet = new ArrayList<String>();
		//System.out.println("m: "+m+" n: "+n+" tId: " + txId);


		if(m==t.inputList.size()){



			for(int index = 0;index<m;index++){
				//System.out.println("M Index: "+index);
				String oldTxId = t.inputList.get(index).oldTransactionId;
				//System.out.println("Old tx id: "+oldTxId);
				if(!mapWithIndex.containsKey(oldTxId)){
					System.err.println(t.transactionId+": Error! Linked Old Transaction ID not found in ledger");
					return false;
				}
				else{
					indexOfOldTx = mapWithIndex.get(oldTxId);
					old = listOfTransactions.get(indexOfOldTx);
					inputAmt = old.outputList.get(t.inputList.get(index).indexOfOutputTx).amount;
					inputName = old.outputList.get(t.inputList.get(index).indexOfOutputTx).name;

					if(index == 0){
						tempSet.add(inputName);
					}

					if(index>0){
						if(!tempSet.contains(inputName)){
							System.out.println(t.transactionId+": Invalid Transaction: transaction has multiple accounts that own inputs.");
							return false;

						}
					}

					if(balanceMap.get(inputName) >= inputAmt)
					{
						inputSum+=inputAmt;
						//System.out.println("input sum: "+ inputSum + " old input amt: "+inputAmt);

						change = balanceMap.get(inputName) - inputSum;
						changeMap.put(inputName, change);
						//System.out.println("Change: "+change);
					}
					else{
						System.err.println(t.transactionId+": Error! account does not have enough Balance! ");
					}
				}
			}
			if(n==t.outputList.size()){
				for(int index = 0;index<n;index++){
					//System.out.println("here in N");
					if(!(changeMap.containsKey(t.outputList.get(index).name)))
					{
						if(!t.outputList.get(index).name.equals(inputName)){
							//System.out.println("OUTPUT NAME: "+t.outputList.get(index).name+" INPUT NAME: "+inputName+" Balance of output NAME: "+ balanceMap.get(t.outputList.get(index).name)+" CURR AMT: "+t.outputList.get(index).amount);
							if(balanceMap.containsKey(t.outputList.get(index).name))
								changeMap.put(t.outputList.get(index).name, t.outputList.get(index).amount+balanceMap.get(t.outputList.get(index).name));
						}
						else
							changeMap.put(t.outputList.get(index).name, t.outputList.get(index).amount);
					}
					else
					{
						changeMap.put(t.outputList.get(index).name, changeMap.get(t.outputList.get(index).name)+t.outputList.get(index).amount);
					}
					outputSum+=t.outputList.get(index).amount;
				}
			}
			else
			{
				System.err.println(t.transactionId+": Error! The value of n does not equal the no of output pairs");
			}
		}
		else
		{
			System.err.println(t.transactionId+": Error! The value of m does not equal the no of input pairs");
		}

		//System.out.println("Input sum " + inputSum + " Output sum: " + outputSum);
		if(inputSum==outputSum){
			if(!validateSha1(txId, correctSha1 = generateHash(t.toString().substring(10)))){
				System.err.println(t.transactionId+": has failed sha1 validation. Changing transaction id to: " + correctSha1);
			}
			return true;
		}

		else
		{
			System.err.println(t.transactionId+": Input Sum does not match output sum");
			return false;
		}
	}

	private void write(String Transactions, String outputFileName) throws IOException {
		//System.out.println(Transactions);
		File f = new File(outputFileName);
		if (!f.exists() || !f.canWrite())
			System.err.println("Error: file " + outputFileName + " cannot be opened for writing!!!");

		FileWriter fw = new FileWriter(f);
		BufferedWriter br = new BufferedWriter(fw);

		try {
			br.write(Transactions);
		} catch (IOException e) {
			System.err.println("Error: file " + outputFileName + " cannot be opened for writing");
		}finally{
			br.flush();
			br.close();
		}
	}


	public static String readKeyFile(String filename) throws IOException{
		BufferedReader br = null;
		String key = "";
		String line = null;
		try {
			br = new BufferedReader(new FileReader(filename));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			fileRead = false;
			System.err.println("Error: file "+filename+" cannot be opened for reading");
		}
		line = br.readLine();
		while(line!=null){
			key = key+line.replaceAll("-----BEGIN PUBLIC KEY-----", "").replaceAll("-----END PUBLIC KEY-----", "").replaceAll("\n", "").replaceAll("\r", "");
			line = br.readLine();
		}
		//System.out.println("private key: "+key);
		return key;
	}

	public static boolean validateSha1(String txId, String sha1) {
		//System.out.println("Sha1 ID: " +sha1+ " TxID: "+txId);
		if(txId.equals(sha1))
			return true;
		else
			return false;
	}

	private static String generateHash(String string)
	{
	    String _sha1 = "";
	    string += "\n";
	    try{
	        MessageDigest md = MessageDigest.getInstance("SHA-1");
	        md.reset();
	        md.update(string.getBytes("UTF-8"));
	        _sha1 = convertBytestoHex(md.digest());
	    }
	    catch(NoSuchAlgorithmException e){
	        e.printStackTrace();
	    }
	    catch(UnsupportedEncodingException e){
	        e.printStackTrace();
	    }
	    return _sha1.substring(0, 8);
	}

	private static String convertBytestoHex(final byte[] byteArray){
	    Formatter formatter = new Formatter();
	    for (byte b : byteArray){
	        formatter.format("%02x", b);
	    }
	    String result = formatter.toString();
	    formatter.close();
	    return result;
	}
}

// -*- mode: java; c-basic-offset: 2; -*-
// Copyright 2009-2011 Google, All Rights reserved
// Copyright 2011-2012 MIT, All rights reserved
// Released under the Apache License, Version 2.0
// http://www.apache.org/licenses/LICENSE-2.0

package io.qaxh.eth;

import io.qaxh.etherscan.Etherscan;

import com.google.appinventor.components.runtime.Component;
import com.google.appinventor.components.runtime.AndroidNonvisibleComponent;
import com.google.appinventor.components.runtime.ComponentContainer;

import org.web3j.abi.TypeEncoder;
import org.web3j.abi.EventEncoder;
import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.*;
import org.web3j.abi.datatypes.generated.Uint8;
import org.web3j.abi.datatypes.generated.StaticArray10;
import org.web3j.abi.datatypes.generated.Uint256;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.Web3jFactory;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.DefaultBlockParameterNumber;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.*;
import org.web3j.protocol.http.HttpService;
import org.web3j.utils.Numeric;
import org.web3j.utils.Convert;

import org.web3j.protocol.http.HttpService;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.Web3jFactory;

import org.web3j.utils.Numeric;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.DefaultBlockParameterNumber;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Hash;
import org.web3j.tx.RawTransactionManager;
import org.web3j.utils.Convert;
import org.web3j.tx.ManagedTransaction;
import org.web3j.protocol.core.methods.response.EthBlock.TransactionResult;

import org.web3j.abi.FunctionEncoder;
import org.web3j.abi.FunctionReturnDecoder;
import org.web3j.abi.TypeReference;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;

import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.jcajce.provider.digest.Keccak;


import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.*;



import com.google.appinventor.components.annotations.DesignerProperty;
import com.google.appinventor.components.annotations.DesignerComponent;
import com.google.appinventor.components.annotations.PropertyCategory;
import com.google.appinventor.components.annotations.SimpleEvent;
import com.google.appinventor.components.annotations.SimpleFunction;
import com.google.appinventor.components.annotations.SimpleObject;
import com.google.appinventor.components.annotations.SimpleProperty;
import com.google.appinventor.components.annotations.UsesLibraries;
import com.google.appinventor.components.common.ComponentCategory;
import com.google.appinventor.components.common.PropertyTypeConstants;
import com.google.appinventor.components.runtime.util.ErrorMessages;
import com.google.appinventor.components.runtime.util.YailList;

import rx.Subscription;
import rx.functions.Action1;

import android.graphics.Bitmap;
import android.graphics.Color;
import android.app.Activity;
import android.content.ContentValues;
import android.content.Intent;
import android.net.Uri;
import android.os.Environment;
import android.provider.MediaStore;
import android.os.StrictMode;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.*;
import java.util.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;


import java.lang.Throwable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.text.SimpleDateFormat;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Dictionary;
import java.util.Locale;
import java.util.List;
import java.util.Formatter;

class QAXH_ETH_COMPONENT {
  public static final int VERSION = 108;
  public static final String VERSION_STR = "1.08";
}

@DesignerComponent(
        version = QAXH_ETH_COMPONENT.VERSION,
        description = "This component implements ethereum access.",
        category = ComponentCategory.EXTENSION,
        nonVisible = true,
        iconName = "aiwebres/eth.png")
@SimpleObject(external=true)
@UsesLibraries(libraries =
        "abi-3.3.1-android.jar, " +
        "core-1.54.0.0.jar, " +
        "core-3.3.1-android.jar, " +
        "crypto-3.3.1-android.jar, " +
        "jackson-annotations-2.1.4.jar, " +
        "jackson-core-2.1.3.jar, " +
        "jackson-databind-2.1.3.jar, " +
        "javapoet-1.7.0.jar, " +
        "okhttp-3.10.0.jar, " +
        "okio-1.14.1.jar, " +
        "prov-1.54.0.0.jar, " +
        "rlp-3.3.1-android.jar, " +
        "rxjava-1.2.2.jar, " +
        "scrypt-1.4.0.jar, " +
        "slf4j-api-1.7.25.jar, " +
        "slf4j-simple-1.7.25.jar, " +
        "tuples-3.3.1-android.jar, " +
        "utils-3.3.1-android.jar"
        )
public class QAXH_Eth extends AndroidNonvisibleComponent implements Component {

    // VARIABLES

    private static final String LOG_TAG = "QaxhEthComponent";
    private Web3j web3;
    private BigInteger nonce;
    private String privHexKey;
    private BigInteger gasLimit;
    private BigInteger gasPrice;

    // CONSTRUCTOR

    /**
     * Creates a QAXH_Eth component.
     *
     * @param container container, component will be placed in
     */
    public QAXH_Eth(ComponentContainer container) {
        super(container.$form());
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);

        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
        web3 = Web3jFactory.build(new HttpService("https://rinkeby.infura.io/v3/dd30c39429b5422799ed22c6a26c13c7")); //infura: jose.luu@free.fr qaxh-eth-1-public
        gasLimit = BigInteger.valueOf(500000); // default gas limit
        nonce = null;

        try {
            gasPrice = web3.ethGasPrice().send().getGasPrice();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }

   /**
    *   @param relayNodeUrl the new relayNodeUrl Url.
    */
    @SimpleFunction(description = "Set the RelayNodeUrl")
    public void blockchainRelayNodeSetUrl(String relayNodeUrl)
    {
        HttpService service = new HttpService(relayNodeUrl);
        web3 = Web3jFactory.build(service);
    }

    @SimpleFunction(description = "Return the Eth extension version.")
    public String blockchainGetVersion() {
        return String.valueOf(QAXH_ETH_COMPONENT.VERSION_STR);
    }


    // PUBLIC FUNCTIONS (appInventor blocks API)

    /**
     * Setup the private key and nonce private variables used in the extension.
     *
     * @param privHexKey appInventor private key.
     */
    @SimpleFunction(description="Setup the private key and nonce references in QAXH_Auth extension.")
    public void blockchainCreateAccount(String privHexKey) {
        try {
            Credentials credentials = Credentials.create(privHexKey);
            String publicAddress = credentials.getAddress();
            EthGetTransactionCount transactionCount = web3.ethGetTransactionCount(publicAddress, DefaultBlockParameterName.LATEST).send();
            this.nonce = transactionCount.getTransactionCount();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        this.privHexKey = privHexKey;
    }

    @SimpleFunction (description = "Create an keyLabel / address pair")
    public String blockchainCreateAddress() {
        ECPublicKey publicKey;
        ECPrivateKey privateKey;
        BigInteger priv = BigInteger.ZERO;
        ECPoint pubPoint;
        BigInteger pubX = BigInteger.ZERO;
        BigInteger pubY = BigInteger.ZERO;
        boolean oddY=false;
        try {
            ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("secp256k1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA","SC");
            kpg.initialize(ecParamSpec, new SecureRandom());
            KeyPair keyPair=kpg.generateKeyPair();
            publicKey=(ECPublicKey)keyPair.getPublic();
            privateKey=(ECPrivateKey)keyPair.getPrivate();
            priv=privateKey.getS();
            pubPoint=publicKey.getW();
            pubX=pubPoint.getAffineX();
            pubY=pubPoint.getAffineY();
            oddY = pubY.testBit(0);
        } catch(Exception e) {
            e.printStackTrace();
        }
        return "0x" + priv.toString(16) + "/0x" + Keys.getAddress(pubX.toString(16) + pubY.toString(16));
    }

    /**
     * Generate an ethereum private / public key pair.
     *
     * @return the keys and address of the account, in format : Ox <privateKey> /0x04 <publicKeys> /Ox <adress>
     */
    @SimpleFunction (description = "Generate an ethereum private / public key pair.")
    public String blockchainCreateKeyTriplet() {
        ECPublicKey publicKey;
        ECPrivateKey privateKey;
        BigInteger priv = BigInteger.ZERO;
        ECPoint pubPoint;
        BigInteger pubX = BigInteger.ZERO;
        BigInteger pubY = BigInteger.ZERO;
        boolean oddY=false;
        try {
            ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("secp256k1");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA","SC");
            kpg.initialize(ecParamSpec, new SecureRandom());
            KeyPair keyPair=kpg.generateKeyPair();
            publicKey=(ECPublicKey)keyPair.getPublic();
            privateKey=(ECPrivateKey)keyPair.getPrivate();
            priv=privateKey.getS();
            pubPoint=publicKey.getW();
            pubX=pubPoint.getAffineX();
            pubY=pubPoint.getAffineY();
            oddY = pubY.testBit(0);
        } catch(Exception e) {
            e.printStackTrace();
        }
        return "0x" + priv.toString(16) + "/0x04" + pubX.toString(16) +  pubY.toString(16) + "/0x" + Keys.getAddress(pubX.toString(16) + pubY.toString(16));
    }

    /**
     * Give the keccak hash of a string
     *
     * @param message, message to hash.
     * @return hash value as hexadecimal encoded string.
     */
    @SimpleFunction(description = "Computes the Keccak-256 of the string parameter.")
    public String blockchainKeccak(String message) {
        return Hash.sha3String(message);
    }

    @SimpleFunction(description = "Returns the balance of an account.")
    public String blockchainReadBalance(String address) {
        try {
            return web3.ethGetBalance(address.toUpperCase(Locale.US), DefaultBlockParameterName.LATEST)
                .send()
                .getBalance()
                .toString();
        }
        catch (IOException e) {
          return "Could not reach network";
        }
    }

    @SimpleFunction(description = "Returns the current block number.")
    public String blockchainReadBlockNumber() {
        try {
          return web3.ethBlockNumber().send().getBlockNumber().toString();
        }
        catch (IOException e) {
          return "could not reach network";
        }
    }

    /*
   * Get the timestamp of a block
   *
   */
   @SimpleFunction(description = "Retrieves the timestamp of a block")
   public String blockchainReadBlockTimestamp(String blockNumber) {
        EthBlock ethBlock;
        try {
          ethBlock = web3.ethGetBlockByNumber(new DefaultBlockParameterNumber(new BigInteger(blockNumber)),true).send();
        }
        catch (IOException e) {
          return ("Problem connecting to network in getBlockTimestamp");
        }
        if (ethBlock.getBlock() == null) {
          return "not mined";
        }
        return ethBlock.getBlock().getTimestamp().toString();
    }

    @SimpleFunction(description = "Returns relay node client version.")
    public String blockchainRelayNodeGetVersion(){
        try {
          return web3.web3ClientVersion().send().getWeb3ClientVersion();
        }
        catch (IOException e) {
          return "Could not get version: could not reach network";
        }
    }

    /**
     * List all the transactions received by a given address from block number fromBlock to block number fromBlock + numberOfBlocks.
     *
     * @param address, the address of the user to retrieve received transactions for.
     * @param firstBlockNumber, the block umber to start from
     * @param howMuchBlocks, the number of blocks to read
     * @return the last block read / a list of received transaction, encoded in a String
     * ex : the last block read number / 0x... / 0x... / 0x...
     */
    @SimpleFunction(description = "List all the transactions received by a given address from block n° fromBlock to block n° fromBlock + numberOfBlocks.")
    public String blockchainReadReceivedBlock(String address, String firstBlockNumber, int howMuchBlocks) { //int --> Uint ?: can the "howMuchBlocks" field be negative ? (if yes, is it a reverse reading ?)
        BigInteger block = new BigInteger(firstBlockNumber);
        BigInteger toBlock = block.add(BigInteger.valueOf(howMuchBlocks));
        String result = "";
        for (; !block.equals(toBlock); block = block.add(BigInteger.ONE)) {
            try {
                EthBlock ethBlock = web3.ethGetBlockByNumber(new DefaultBlockParameterNumber(block), true).send();
                List<TransactionResult> listTx = ethBlock.getBlock().getTransactions();
                for (TransactionResult txR : listTx) {
                    org.web3j.protocol.core.methods.response.Transaction tx = (org.web3j.protocol.core.methods.response.Transaction) txR.get();
                    if (tx.getTo() != null && blockchainChecksumAddress(tx.getTo()).equals(blockchainChecksumAddress(address))) {
                        result += tx.getHash() + "/";
                    }
                }
            } catch (IOException e) {
                return "Problem connecting to network";
            }
        }
        return block.toString() + "/" + result;
    }

    @SimpleFunction(description = "Returns the token balance of an address.")
    public String blockchainERC20ReadBalance(String tokenContractAddress, String address) {
      Function function = new Function(
        "balanceOf",
        Arrays.<Type>asList(new Address(address)),
        Arrays.<TypeReference<?>>asList(new TypeReference<Uint256>() {
      }));

      List<Uint256> lst = callViewFunction(tokenContractAddress, function);
      return lst.get(0).getValue().toString();
    }

    /**
     * Retrieve the details of a transaction.
     *
     * @param String transaction_0x, the hexadecimal id of a transaction
     * @return if the network is reachable : a String with the block, sender, receiver, amount and date; if not, a String Error.
     */
    @SimpleFunction(description = "Retrieve the details of a transaction.")
    public List<String> blockchainReadTransactionDetails(String transaction_0x) {
        EthTransaction ethTx;
        try {
          ethTx=web3.ethGetTransactionByHash(transaction_0x).send();
        }
        catch (IOException e) {
          return new ArrayList();
        }
        org.web3j.protocol.core.methods.response.Transaction tx = ethTx.getTransaction();
        if (tx == null) {
          return new ArrayList();
        }
        BigInteger blockNumber=tx.getBlockNumber();;
        EthBlock ethBlock;
        BigInteger gasUsed;
        TransactionReceipt transactionReceipt;
        try {
          ethBlock = web3.ethGetBlockByNumber(new DefaultBlockParameterNumber(blockNumber),true).send();
          transactionReceipt =
             web3.ethGetTransactionReceipt(transaction_0x).send().getTransactionReceipt();
                  gasUsed = transactionReceipt.getGasUsed();
        }
        catch (IOException e) {
          return new ArrayList();
        }
        String from = tx.getFrom();
        String to = tx.getTo();
        BigInteger amount = tx.getValue();
        String inputData = tx.getInput();
        BigInteger gasPriceTx = tx.getGasPrice();
        BigInteger fee = gasPriceTx.multiply(gasUsed);
        BigInteger timestamp;
        String timestampStr;
        if (ethBlock != null && ethBlock.getBlock() != null){
          timestamp =  ethBlock.getBlock().getTimestamp();
          SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");
          Date dt = new Date(timestamp.longValue()*1000);
          timestampStr=sdf.format(dt);
        } else {
          timestampStr = "not mined";
        }
        List<String> ret = new ArrayList();
        ret.add(blockNumber.toString());
        ret.add(from);
        ret.add(to);
        ret.add(amount.toString());
        ret.add(fee.toString());
        ret.add(timestampStr);
        ret.add(inputData);

    // Laisser le contrat à la fin pour ne pas casser l'app de Cyril
        ret.add(transactionReceipt.getContractAddress());

        return ret;
    }

    /**
     * Get the status of a transaction.
     *
     * @param String transactionId, the hexadecimal id of the transaction to scan
     * @return a String, describing the status if successful, with a Error : + explanation if not.
     */
    @SimpleFunction(description = "Retrieves the status of a transaction.")
    public String blockchainReadTransactionStatus(String transaction_0x) {
        EthTransaction ethTx;
        try {
          ethTx=web3.ethGetTransactionByHash(transaction_0x).send();
        }
        catch (IOException e) {
          return "Error: getTransactionStatus could not reach network";
        }
        try {
            EthGetTransactionReceipt ethTxReceipt = web3.ethGetTransactionReceipt(transaction_0x).send();
            TransactionReceipt txReceipt = ethTxReceipt.getTransactionReceipt();
            if (txReceipt == null)
                return "Pending";
            if (txReceipt.getStatus().equals("0x1"))
                return String.format("Mined in block#" + txReceipt.getBlockNumberRaw() + "Gas used: %d",txReceipt.getGasUsed());
            return String.format("Transaction has failed with status: %s. Gas used: %d. (not-enough gas?)", txReceipt.getStatus(), txReceipt.getGasUsed());
        }
        catch (Exception e) { }
        return "failed to poll status for transaction " + transaction_0x;
    }

    @SimpleFunction(description = "Get the lists of received and sent transaction for an address, using the etherscan API")
    public YailList blockchainReadTxLists(String address, String startNumber, String endNumber ) {
        Etherscan client = new Etherscan();
        List[] res = new List[2];
        try {
            res = client.main(address, startNumber, endNumber);
        } catch (IOException e) {
            //do nothing
        }
        YailList list = new YailList();
        List<YailList> res2 = new ArrayList<YailList>();
        res2.add(list.makeList(res[0]));
        res2.add(list.makeList(res[1]));
        return list.makeList(res2);
    }


    /// Utility Functions

    /**
     *
     * Return the given address with an EIP55 checksum.
     *
     */
    @SimpleFunction(description = "Return the given address with an EIP55 checksum.")
    public String blockchainChecksumAddress(String address) {
        return Keys.toChecksumAddress(address);
    }

    /**
     * Send Gwei = 10-9 ether.
     *
     * @param String privKeyHex, the private key of the sending account in hexadecimal
     * @param String dest, the address of the receiver in hexadecimal
     * @param String howMuchGwei, number of Gwei to send
     * @param String data, the data to encript in the transaction, usually the identity hash here
     * @return the transaction hash if successful, if not a String Error : with an explaination of why it failed.
     */
    @SimpleFunction (description = "Send Gwei = 10-9 ether.")
    public String blockchainTransferEtherTo(String address, String howManyWei, String data)
    {
        Credentials credentials = Credentials.create(this.privHexKey);
        if (nonce == null)
            setupNonce(this.privHexKey);
        try {
            BigInteger value = new BigInteger(howManyWei);
            RawTransaction rawTransaction = RawTransaction.createTransaction(this.nonce, gasPrice, gasLimit, address, value, data);
            byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
            String hexValue = Numeric.toHexString(signedMessage);
            EthSendTransaction ethSendTransaction = web3.ethSendRawTransaction(hexValue).sendAsync().get();
            nonce = nonce.add(BigInteger.valueOf(1));
            return ethSendTransaction.getTransactionHash();
        } catch (Exception e) {
            e.printStackTrace();
            return "Error when calling `sendEther`";
        }
    }

    /**
     * Transfer ERC20 tokens to an address.
     *
     * @param to Address of the receiver.
     * @param amount Amount of tokens to be sent.
     * @param token Address of the ERC20 contract.
     * @return The transaction tx hash.
     */
    @SimpleFunction(description="Transfer ERC20 tokens to an address")
    public String blockchainERC20TransferTo(String to, String amount, String token) {
        Function function = new Function(
                "transfer",
                Arrays.<Type>asList(
                        new Address(to),
                        new Uint256(new BigInteger(amount))
                ),
                Arrays.<TypeReference<?>>asList(new TypeReference<Bool>(){})
        );
        return callNonViewFunction(token, function);
    }

    // Private functions

    private List callViewFunction(String contractAddress, Function function) {
        Credentials credentials = Credentials.create(this.privHexKey);
        String address = credentials.getAddress();
        String encodedFunction = FunctionEncoder.encode(function);
        Transaction transaction = Transaction.createEthCallTransaction(address, contractAddress, encodedFunction);
        try {
            EthCall response = web3.ethCall(transaction, DefaultBlockParameterName.LATEST).sendAsync().get();
            return FunctionReturnDecoder.decode(response.getValue(), function.getOutputParameters());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private String callNonViewFunction(String contractAddress, Function function) {
        Credentials credentials = Credentials.create(this.privHexKey);
        try {
            String encodedFunction = FunctionEncoder.encode(function);
            RawTransaction rawTransaction = RawTransaction.createTransaction(nonce, gasPrice, gasLimit, contractAddress, encodedFunction);
            byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, credentials);
            String hexValue = Numeric.toHexString(signedMessage);
            String txHashLocal = Hash.sha3(hexValue);
            EthSendTransaction ethSendTransaction = web3.ethSendRawTransaction(hexValue).send();
            nonce = nonce.add(BigInteger.valueOf(1));
            return txHashLocal;
        } catch (Exception e) {
            e.printStackTrace();
            return "error: callNonViewFunction";
        }
    }

    private void setupNonce(String privateKey) {
        try {
            Credentials credentials = Credentials.create(privateKey);
            String publicAddress = credentials.getAddress();
            EthGetTransactionCount transactionCount = web3.ethGetTransactionCount(publicAddress, DefaultBlockParameterName.LATEST).send();
            nonce = transactionCount.getTransactionCount();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
       /**
     * Convert  bytes32 to String
     *
     * @param Bytes32
     * @return String
     */

     public static String HexString32BToJavaString(Bytes32 Hex){
        String HexString = "0x"+TypeEncoder.encode(Hex);
        int dim = 0;
        for(int i=2;i< HexString.length();i = i+2)
        {
            if(HexString.charAt(i)!= '0' || HexString.charAt(i+1)!= '0')
                dim ++;

        }



        String hex = HexString.substring(2,dim*2+2);
        int l = hex.length();
        byte[] bytes = new byte[l / 2];
        for (int i = 0; i < l; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        String value = new String(bytes,StandardCharsets.UTF_8);
        return value;

    }

     /**
     * Convert string to bytes32
     *
     * @param string
     * @return bytes32
     */

    public static Bytes32 JavaStringToHexString32B(String word){



        String firsthex =  String.format("0x%064x", new BigInteger(1, word.getBytes()));

        char[] ch = new char[firsthex.length()];

        // Copy character by character into array
        for (int i = 0; i < firsthex.length(); i++) {

            ch[i] = firsthex.charAt(i);
        }
        int dim = firsthex.length() - word.length()*2;
        int dim2 =firsthex.length();
        // b.length - c.length , b.length

        char[] newArray = Arrays.copyOfRange(ch, dim , dim2);


        for (int i = 2 , j = 0 ; i < word.length()*2 + 2 ; i ++ , j++)
        {
            ch[i] = newArray[j];
        }
        for (int i = 2 + word.length()*2; i < firsthex.length(); i++) {

            ch[i] = '0';
        }
        String ar ="";

        for(int i=0; i< firsthex.length(); i++)
        {ar += ch[i];}
        System.out.println(ar);

        return new Bytes32(
                Numeric.hexStringToByteArray(ar));
    }

      /**
     * Convert HexString to Ascii String
     *
     *
     */

       public static String HexStringToAsciiString(String HexString)
    {    if(!(HexString.charAt(0) == '0' && HexString.charAt(1) == 'x'))
           {HexString = "0x"+ HexString;}
        int dim = 0;
        for(int i=2;i< HexString.length();i = i+2)
        {
            if(HexString.charAt(i)!= '0' || HexString.charAt(i+1)!= '0')
                dim ++;

        }



        String hex = HexString.substring(2,dim*2+2);
        int l = hex.length();
        byte[] bytes = new byte[l / 2];
        for (int i = 0; i < l; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        String value = new String(bytes,StandardCharsets.UTF_8);
        return value;
    }

     @SimpleFunction(description="From Hex Form to Ascii Form")
       private static String FromHexStringToAsciiString(String HexString)
    {    if(!(HexString.charAt(0) == '0' && HexString.charAt(1) == 'x'))
           {HexString = "0x"+ HexString;}
        int dim = 0;
        for(int i=2;i< HexString.length();i = i+2)
        {
            if(HexString.charAt(i)!= '0' || HexString.charAt(i+1)!= '0')
                dim ++;

        }



        String hex = HexString.substring(2,dim*2+2);
        int l = hex.length();
        byte[] bytes = new byte[l / 2];
        for (int i = 0; i < l; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        String value = new String(bytes,StandardCharsets.UTF_8);
        return value;
    }


     /**
     * Convert HexString to Byte
     *
     *
     */

    public static byte[] hexStringToByteArray(String s) {

        if(s.charAt(0) == '0' && s.charAt(1) == 'x')
        {s = s.substring(2);}
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

     /**
     * Check is hex Form or not
     *
     *
     */

    boolean checkHex(String s)
    {
        if(s.charAt(0) == '0' && s.charAt(1) == 'x')
        {s = s.substring(2);}

        // Size of string
        int n = s.length();

        // Iterate over string
        for(int i = 0; i < n; i++)
        {
            char ch = s.charAt(i);

            // Check if the character
            // is invalid
            if ((ch < '0' || ch > '9') &&
                    (ch < 'A' || ch > 'F') && (ch < 'a' || ch > 'f'))
            {

                return false;
            }
        }

        return true;
    }




    /**
     * Convert bytes to hexadecimal
     *
     * @param byte[] bytes, the array of bits to be translated
     * @return a string containing the transalation in hexadecimal
     */
    public static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    @SimpleFunction(description="Get Name, Symbol and decimal of an ERC20")
    public List<String> blockchainERC20ReadVariables (String ERC20) {

        List<String> result = new ArrayList<String>();

        Function get_name = new Function (
            "name",
            Collections.<Type>emptyList(),
            Collections.<TypeReference<?>>singletonList(new TypeReference<Utf8String>(){
            })
        );
        List<Utf8String> lst_n = callViewFunction(ERC20, get_name);
        result.add(lst_n.get(0).toString());

        Function get_symbol = new Function (
            "symbol",
            Collections.<Type>emptyList(),
            Collections.<TypeReference<?>>singletonList(new TypeReference<Utf8String>(){
            })
        );
        List<Utf8String> lst_s = callViewFunction(ERC20, get_symbol);
        result.add(lst_s.get(0).toString());

        Function get_decimals = new Function (
            "decimals",
            Collections.<Type>emptyList(),
            Collections.<TypeReference<?>>singletonList(new TypeReference<Uint256>(){
            })
        );
        List<Uint256> lst_d = callViewFunction(ERC20, get_decimals);
        result.add(lst_d.get(0).getValue().toString());

        return result;
    }

    @SimpleFunction(description="Get gasLimit in Gwei")
    public String blockchainGasLimitGet(){
        return gasLimit.toString();
    }

    @SimpleFunction(description="Set gasLimit in Gwie")
    public void blockchainGasLimitSet(String gasUnit){
        gasLimit = new BigInteger(gasUnit);
    }

    @SimpleFunction(description="Get gasPrice in Gwie")
    public List<String> blockchainGasPriceGet(){
        List<String> result = new ArrayList<String>();

        BigDecimal currentGasPrice = Convert.fromWei(gasPrice.toString(), Convert.Unit.GWEI);

        result.add(currentGasPrice.toBigInteger().toString());
        try {
            String w3j_gasPrice = web3.ethGasPrice().send().getGasPrice().toString();
            currentGasPrice = Convert.fromWei(w3j_gasPrice, Convert.Unit.GWEI);
            result.add(currentGasPrice.toBigInteger().toString());
        }
        catch (IOException e) {
            result.add("Error: getGasPrice could not reach network");
            return result;
        }
        return result;
    }

    @SimpleFunction(description="Set gasPrice in Gwie")
    public void blockchainGasPriceSet(String gwei) {
        BigDecimal newGasPrice_BD = Convert.toWei(gwei, Convert.Unit.GWEI);
        gasPrice = newGasPrice_BD.toBigInteger();
    }

    // Fin des fonctions Rinkeby_ETH

}

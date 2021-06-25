package io.qaxh.etherscan;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.List;
import java.util.ArrayList;

import javax.net.ssl.HttpsURLConnection;

import org.json.*;
import org.web3j.crypto.Keys;

public class Etherscan {

    private String ApiKeyToken = "UUWBFD69V1Z262ACNIU4I7P5E1TGU79YZJ";

    private List<String> receivedTx = new ArrayList<String>();
    private List<String> sentTx = new ArrayList<String>();

    public List[] main(String address, String start, String end) throws IOException

    {
        String url = "";
        if (start.equals("/") || end.equals("/")) {
            url = constructUrl(address, start, end);
        } else {
        url = constructUrl(address, start, end);
        }

        //System.out.println(getJsonFromUrl(url));

        try {
            JSONObject json = new JSONObject(getJsonFromUrl(url));
            JSONArray txList = json.getJSONArray("result");
            handle(txList, address);
        } catch (JSONException e) {
            receivedTx.clear();
            receivedTx.add("couldn't get received tx");
            sentTx.clear();
            sentTx.add("couldn't get sent tx");
        }
        List[] res = new List[2];
        res[0] = receivedTx;
        res[1] = sentTx;
        return res;
        //return [ArrayToString(receivedTx), ArrayToString(sentTx)];
    }

    public String constructUrl(String address, String startBlock, String endBlock) {
        String url = "http://api-rinkeby.etherscan.io/api?" +
                "module=account&action=txlist&" +
                "address=" + address + "&" +
                "startblock=" + startBlock + "&endblock=" + endBlock + "&" +
                "sort=asc&apikey=" + ApiKeyToken;
        return url;
    }

    public String constructUrl(String address) {
        return constructUrl(address, "0", "latest");
    }

    public String getJsonFromUrl(String url) throws IOException {

        okhttp3.OkHttpClient client = new okhttp3.OkHttpClient();

        okhttp3.Request request = new okhttp3.Request.Builder()
                .url(url)
                .build();

        okhttp3.Response response = client.newCall(request).execute();
        return response.body().string();


        /*
        URL obj = new URL(null, url , new sun.net.www.protocol.https.Handler());

        //URL obj = new URL(url);
        HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();

        //add reqest header
        con.setRequestMethod("GET");

        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        return response.toString();
        */
    }

    public void handle(JSONArray list, String address) throws JSONException {
        int length = list.length();
        JSONObject e;
        for (int i = 0 ; i < length ; i++) {
            JSONObject tx = list.getJSONObject(i);
            if (toCheckSumAddress(tx.getString("from")).equals(address)){
            	sentTx.add(tx.getString("hash"));
            } else {
	            receivedTx.add(tx.getString("hash"));
            }
        }
    }

    private String ArrayToString(List<String> list) {
    	String res = "";
    	for (String e : list) {
    		res += e + "/";
	    }
	    return res.substring(0, res.length() - 1);
    }

    private String toCheckSumAddress (String address) throws JSONException {
    	return Keys.toChecksumAddress(address);
    }
}

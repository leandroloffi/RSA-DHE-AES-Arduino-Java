
import expr.Expr;
import expr.Parser;
import expr.SyntaxException;
import model.FDR;

import java.io.IOException;
import java.net.*;
//import java.util.Base64;

public class Receiver {

    private static final int DEFAULT_PORT = 8888;
    private DatagramSocket serverSocket;
    private KeyGenerator keyGenerator;
    private static final String SEPARATOR = "#";
    private boolean keyExchangeCompleted = false;

    private int publicKeyClient;
    private int iv;

    private FDR fdr;

    private static final String HELLO_MESSAGE = "hello";
    private static final String DONE_MESSAGE = "done";
    private static final String HELLO_ACK = "#";
    private static final String DONE_ACK = "!";

    private boolean clientHello = false;
    private boolean clientDone = false;
    private boolean chaveRSArecebida = false;
    private boolean chaveDHrecebida = false;

    public static void main(String[] args) throws Exception {
        int port = args.length == 0 ? DEFAULT_PORT : Integer.parseInt(args[0]);
        new Receiver().run(port);
    }

    public void run(int port) throws Exception {
        try {
            serverSocket = new DatagramSocket(port);
            byte[] receiveData = new byte[24];

            System.out.printf("Listening on udp:%s:%d%n",
                    InetAddress.getLocalHost().getHostAddress(), port);
            DatagramPacket receivePacket = new DatagramPacket(receiveData,
                    receiveData.length);

            while (true) {
                serverSocket.receive(receivePacket);
                String sentence = new String(receivePacket.getData(), 0,
                        receivePacket.getLength());

                // now send acknowledgement packet back to sender
                InetAddress IPAddress = receivePacket.getAddress();

                keyGenerator = new KeyGenerator();

                /* Pega chave pública do Cliente. */
                try {

                    if (!clientHello)
                        processClientHello(sentence, IPAddress, port);
                    else if (sentence.equals(DONE_MESSAGE))
                        processClientDone(sentence, IPAddress, port);
                    else if (clientHello && !chaveRSArecebida)
                        processRSAKeyExchange(sentence, IPAddress, port);
                    else if (clientHello && !chaveDHrecebida)
                        processDiffieHellmanKeyExchange(sentence, IPAddress, port);


                    /* Se a troca de chaves estiver completa, realiza a troca de dados. */
                    if (isTheKeyExchangeCompleted()) {
                        System.out.println("Texto recebido em HEXA: " + StringHandler.convertByteToHex(receivePacket.getData()));
//		    	  byte[] array = new byte[receivePacket.getData().length];
//		    	  array = receivePacket.getData();
//		    	  ModoCBC modoCBC = new ModoCBC();
//		    	  String keyHex = Integer.toHexString(keyGenerator.getKey());
//		    	  String keyString = "";
//
//		    	  for (int i = 0; i < 16; i++) { keyString += keyHex; }
//		    	  String str = convertByteToHex(receivePacket.getData());
//		    	  System.out.println("Texto decifrado: " + modoCBC.decipher(keyString, str));

                    }
                } catch (IOException e) {
                    System.out.println(e);
                }
                // should close serverSocket in finally block
            }
        } catch (IOException e) {
            System.out.println(e);
        }
    }

    int countTeste = 2;

    private int handleIv(int iv, FDR fdr) {
        Expr expr = null;
        String operation = String.valueOf(iv) + fdr.getOperator() + String.valueOf(fdr.getOperand());
        try {
            expr = Parser.parse(operation);
        } catch (SyntaxException e) {
            e.printStackTrace();
        }

        return (int) expr.value();
    }

    private void done() {
        clientDone = true;
        clientHello = false;
        chaveRSArecebida = false;
        chaveDHrecebida = false;

    }

    private void sendMessage(String sendString, DatagramSocket serverSocket, InetAddress IPAddress, int port) throws IOException {
        byte[] sendData = sendString.getBytes("UTF-8");
        DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, IPAddress, port);
        serverSocket.send(sendPacket);
    }

    private void processClientHello(String sentence, InetAddress IPAddress, int port) throws IOException {
        System.out.println("\n******HELLO CLIENT AND SERVER******");
        if (sentence.equals(HELLO_MESSAGE)) {
            sendMessage(HELLO_ACK, serverSocket, IPAddress, port);
            clientHello = true;
            System.out.println("Hello Client and Server Successful");
            System.out.println("***********************************\n");
            clientDone = false;
        }
    }

    private void processClientDone(String sentence, InetAddress IPAddress, int port) throws IOException {
        System.out.println("\n*******DONE CLIENT AND SERVER*******");
        sendMessage(DONE_ACK, serverSocket, IPAddress, port);
        System.out.println("Done Client and Server Successful");
        System.out.println("***********************************\n");

        done();
    }

    private void processRSAKeyExchange(String sentence, InetAddress IPAddress, int port) throws IOException {

        /*Recebe chave pública cliente e IV*/
        System.out.println("******RECEIVED RSA CLIENT KEY******");
        //System.out.println("Chave RSA recebida: " + sentence);
        publicKeyClient = StringHandler.getPublicKeyClient(sentence);
        iv = StringHandler.getIvRSAExchange(sentence);
        fdr = StringHandler.getFdrRSAClient(sentence);
        System.out.println("RSA Public Key: " + publicKeyClient);
        System.out.println("Iv: " + iv);
        System.out.println("Fdr: iv (" + iv + ") " + fdr.getOperator() + " " + fdr.getOperand());
        chaveRSArecebida = true;
        System.out.println("***********************************\n");

                    /* Envia chave pública e iv. */
        System.out.println("*******SEND RSA SERVER KEY*********");

        String sendString = keyGenerator.getPublicKey() + SEPARATOR + handleIv(iv, fdr);
        sendMessage(sendString, serverSocket, IPAddress, port);

        System.out.println("Chave pública do servidor: " + keyGenerator.getPublicKey());
        System.out.println("Iv: " + handleIv(iv, fdr));
        System.out.println("***********************************\n");
    }

    private void processDiffieHellmanKeyExchange(String sentence, InetAddress IPAddress, int port) throws IOException {

        System.out.println("*******RECEIVED DH CLIENT KEY******");
        keyGenerator.setBase(StringHandler.getBaseClient(sentence));
        keyGenerator.setModulus(StringHandler.getModulusClient(sentence));
        keyGenerator.setSimpleKey(keyGenerator.getKeyBase(StringHandler.getDiffieHellmanKeyClient(sentence)));
        iv = StringHandler.getIvDiffieHellmanClient(sentence);

        chaveDHrecebida = true;
        //System.out.println("\n*** Chave Diffie-Hellman recebida! ***");
        System.out.println("Diffie-Hellman Key: " + StringHandler.getDiffieHellmanKeyClient(sentence));

        System.out.println("base: " + StringHandler.getBaseClient(sentence));
        System.out.println("modulus: " + StringHandler.getModulusClient(sentence));
        System.out.println("iv: " + StringHandler.getIvDiffieHellmanClient(sentence));
        System.out.println("***********************************\n");

                    /* Envia chave Diffie-Hellman e IV. */
        System.out.println("*********SEND DH SERVER KEY*******");
        String sendString = keyGenerator.getKey() + SEPARATOR + (iv + 1);
        System.out.println("Iv: " + iv);

        sendMessage(sendString, serverSocket, IPAddress, port);

        System.out.println("Diffie-Hellman Key: " + keyGenerator.getKey());
        System.out.println("***********************************\n");

        System.out.println("*SYMMETRICAL SESSION CLIENT-SERVER*");
        System.out.println("Session Key: " + keyGenerator.getSimpleKey());
        System.out.println("***********************************\n");

    }

    private boolean isTheKeyExchangeCompleted() {
        if (clientHello && !clientDone && chaveRSArecebida && chaveDHrecebida)
            return true;
        return false;
    }

}

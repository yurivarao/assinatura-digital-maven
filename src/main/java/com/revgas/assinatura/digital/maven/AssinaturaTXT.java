package com.revgas.assinatura.digital.maven;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class AssinaturaTXT {

    public String local_documento;
    public String local_assinado;
    static public String local_keystore; 
    
    public void assinar(String localdocumento, String localKeystore, String nomeKeyStore, String senhaKeyStore, String senhaPrivateKey, 
        String nomeCertificado) throws Exception{
        
        local_documento = localdocumento;
        local_keystore = localKeystore;
        
        // Gera o par de chaves
        KeyPair pair = generateKeyPair();
        
        // Pega o par de chaves da KeyStore
        // KeyPair pair = getKeyPairFromKeyStore(nomeKeyStore, senhaKeyStore, senhaPrivateKey, nomeCertificado);
        // Par de chaves gerada com o comando (em Linux):
        // keytool -genkeypair -alias mykey -storepass store123 -keypass key123 -keyalg RSA -keystore keystore.jks
        
        // Ler mensagem do arquivo
        AssinaturaTXT assD = new AssinaturaTXT();
        String mensagem = assD.lerArquivo(local_documento);
        
        // Criptografa a mensagem
        String TextoCifrado = criptografa(mensagem, pair.getPublic());
        
        // Assina digitalmente a mensagem
        String assinatura = assinatxt(TextoCifrado, pair.getPrivate());

        // Verifica a assinatura
        boolean valido = verificaAssinatura(TextoCifrado, assinatura, pair.getPublic());
        if(valido == true){
            System.out.println("Assinatura Válida");
        }else{
            System.out.println("Assinatura Inválida");
        }
        
        // Cria o arquivo assinado
        assD.criaArquivo(mensagem, assinatura, local_documento);
    }
    
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    public static KeyPair getKeyPairFromKeyStore(String nomeKeyStore, 
        String senhaKeyStore, String senhaPrivateKey, String nomeCertificado) throws Exception {

        InputStream ins = AssinaturaTXT.class.getResourceAsStream(local_keystore);

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, senhaKeyStore.toCharArray());
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(senhaPrivateKey.toCharArray()); 
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(nomeCertificado, keyPassword);
        java.security.cert.Certificate cert = keyStore.getCertificate(nomeCertificado); 
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static String criptografa(String mensagem, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] TextoCifrado = encryptCipher.doFinal(mensagem.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(TextoCifrado);
    }

    public static String assinatxt(String TextoCifrado, PrivateKey privateKey) throws Exception {
        Signature assina = Signature.getInstance("SHA256withRSA");
        assina.initSign(privateKey);
        assina.update(TextoCifrado.getBytes(UTF_8));
        byte[] assinatura = assina.sign();
        System.out.println("Documento Assinado");
        return Base64.getEncoder().encodeToString(assinatura);
    }

    public static boolean verificaAssinatura(String TextoCifrado, String assinatura, PublicKey publicKey) throws Exception {
        Signature verifica = Signature.getInstance("SHA256withRSA");
        verifica.initVerify(publicKey);
        verifica.update(TextoCifrado.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(assinatura);

        return verifica.verify(signatureBytes);
    }
    
    public String lerArquivo(String local_documento) throws FileNotFoundException, IOException{
        String mensagem = "";
        
        try {
            FileReader arquivo = new FileReader(local_documento);
            
            BufferedReader br = new BufferedReader(arquivo);
            while(br.ready()){
                mensagem += br.readLine();
            } 
        }catch(IOException e){
            System.err.printf("Erro na abertura do arquivo: %s.\n",
            e.getMessage());
        }
        return mensagem;
    }
    
    public void criaArquivo(String mensagem, String assinatura, String local_documento) throws FileNotFoundException, IOException{
        String inicioAssinatura = "\r\n\n------------------BEGIN SIGNATURE-----------------\r\n\n";
	String finalAssinatura = "\r\n\n-------------------END SIGNATURE------------------";
        
        /* Lê o nome do arquivo
        File file = new File(local_documento);
        local_assinado = file.getName();
        int tamanho = local_assinado.length();
        if(local_assinado.endsWith(".txt")){
            local_assinado = local_assinado.substring(0, tamanho-4);
        }else{
            System.out.println("Não foi possivel ler o nome do documento original, será atribuído um nome padrão...");
            local_assinado = "Documento";
        }
        */ 
        int tamanho = local_documento.length();
        if (local_documento.endsWith(".txt")){
            local_assinado = local_documento.substring(0, tamanho-4);
        } else {
            System.out.println("Não foi possivel ler o nome do documento original");
        }
        
        // Define o caminho de destino contendo o nome original do arquivo
        try (
            FileOutputStream out = new FileOutputStream(local_assinado + "Assinado.txt")) {
            out.write(mensagem.getBytes(), 0, mensagem.length());
            out.write(inicioAssinatura.getBytes(), 0, inicioAssinatura.length());
            int count = 0;
            int ler = 0;
            String linha = "\n";
            for (int i=0; i <= assinatura.length(); i++){    
                if (count == 50){
                    out.write(assinatura.getBytes(), ler, count);
                    out.write(linha.getBytes());
                    count = 0;
                    ler = ler + 50;
                }if (i == assinatura.length()){
                    out.write(assinatura.getBytes(), ler, count);
                }else{
                    count++;
                }    
            }    
            out.write(finalAssinatura.getBytes(), 0, finalAssinatura.length());
        }
    }
    
    public String retornaAssinatura(String localdocumento, String localKeystore, String nomeKeyStore, String senhaKeyStore, String senhaPrivateKey, 
        String nomeCertificado) throws Exception{
        
        local_documento = localdocumento;
        local_keystore = localKeystore;
        
        // Gera o par de chaves
        KeyPair pair = generateKeyPair();
        
        // Pega o par de chaves da KeyStore
        // KeyPair pair = getKeyPairFromKeyStore(nomeKeyStore, senhaKeyStore, senhaPrivateKey, nomeCertificado);
        // Par de chaves gerada com o comando (em Linux):
        // keytool -genkeypair -alias mykey -storepass store123 -keypass key123 -keyalg RSA -keystore keystore.jks
        
        // Ler mensagem do arquivo
        AssinaturaTXT assD = new AssinaturaTXT();
        String mensagem = assD.lerArquivo(local_documento);
        
        // Criptografa a mensagem
        String TextoCifrado = criptografa(mensagem, pair.getPublic());

        // Assina digitalmente a mensagem
        String assinatura = assinatxt(TextoCifrado, pair.getPrivate());
        
    return assinatura;
    }
}
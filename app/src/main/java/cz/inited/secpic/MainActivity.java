package cz.inited.secpic;

import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.ImageView;
import android.widget.Toast;

import org.spongycastle.cms.CMSAlgorithm;
import org.spongycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.spongycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.spongycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.OutputEncryptor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class MainActivity extends AppCompatActivity {

    static int TAKE_PICTURE = 1;
    static String TAG = "SecurePicture";
    static String baseURL = "http://192.168.168.80/inited/Projekty/095-dropick/05-src/phpdecrypt";

    ImageView imageView1;

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                Intent cameraIntent = new Intent(android.provider.MediaStore.ACTION_IMAGE_CAPTURE);
                startActivityForResult(cameraIntent, TAKE_PICTURE);

            }
        });

        imageView1 = (ImageView) findViewById(R.id.imageView1);

        new Thread(new Runnable() {
            @Override
            public void run() {
                downloadCert();
            }
        }).start();



    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent intent) {
        if (requestCode == TAKE_PICTURE && resultCode == RESULT_OK) {

            Bitmap photo = (Bitmap) intent.getExtras().get("data");
            imageView1.setImageBitmap(photo);
            imageView1.setVisibility(View.VISIBLE);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            photo.compress(Bitmap.CompressFormat.JPEG, 85, stream);

            try {

                // nactu si certifikat, kterym budu sifrovat
                CertificateFactory fact = CertificateFactory.getInstance("X.509");
                FileInputStream is = openFileInput("cert.pem");
                X509Certificate cert = (X509Certificate) fact.generateCertificate(is);

                // pripravim si generator
                CMSEnvelopedDataStreamGenerator gen = new CMSEnvelopedDataStreamGenerator();
                gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cert));
                OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

                // sem si zapisu vysledek
                ByteArrayOutputStream baos = new ByteArrayOutputStream();

                // jdu sifrovat
                OutputStream os = gen.open(baos, encryptor);
                os.write(stream.toByteArray());
                os.close();

                byte[] encodedData = baos.toByteArray();
                System.out.println("================================");
//                byte[] encodedValue = Base64.encode(encodedData, Base64.DEFAULT);
//                System.out.println(new String(encodedValue));


                final String fileName = String.valueOf(System.currentTimeMillis() / 1000).concat(".bin");
                Log.i(TAG, "Ukladam do: " + fileName);
                FileOutputStream fos = openFileOutput(fileName, Context.MODE_PRIVATE);
                DataOutputStream dos = new DataOutputStream(fos);
                dos.write(encodedData);
                dos.close();
                fos.close();


                Thread thread = new Thread(new Runnable() {

                    @Override
                    public void run() {
                        try {
                            uploadFile(getFilesDir() + File.separator + fileName);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });

                thread.start();

            } catch (Exception e) {
                System.out.println("exception:" + e);
                e.printStackTrace();
            }

        }
    }


    //android upload file to server
    public int uploadFile(final String filename) {

        Log.i(TAG, "uploadFile");

        int serverResponseCode = 0;

        HttpURLConnection connection;
        DataOutputStream dataOutputStream;
        String lineEnd = "\r\n";
        String twoHyphens = "--";
        String boundary = "*****";


        int bytesRead, bytesAvailable, bufferSize;
        byte[] buffer;
        int maxBufferSize = 1 * 1024 * 1024;
        File selectedFile = new File(filename);


        String[] parts = filename.split("/");
        final String fileName = parts[parts.length - 1];

        if (!selectedFile.isFile()) {
            Log.e(TAG, "Not file: " + filename);
            return 0;
        } else {
            try {
                FileInputStream fileInputStream = new FileInputStream(selectedFile);
                URL url = new URL(baseURL + "/upload.php");
                connection = (HttpURLConnection) url.openConnection();
                connection.setDoInput(true);//Allow Inputs
                connection.setDoOutput(true);//Allow Outputs
                connection.setUseCaches(false);//Don't use a cached Copy
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Connection", "Keep-Alive");
                connection.setRequestProperty("ENCTYPE", "multipart/form-data");
                connection.setRequestProperty("Content-Type", "multipart/form-data;boundary=" + boundary);
                connection.setRequestProperty("uploaded_file", filename);

                //creating new dataoutputstream
                dataOutputStream = new DataOutputStream(connection.getOutputStream());

                //writing bytes to data outputstream
                dataOutputStream.writeBytes(twoHyphens + boundary + lineEnd);
                dataOutputStream.writeBytes("Content-Disposition: form-data; name=\"file\";filename=\""
                        + fileName + "\"" + lineEnd);
                dataOutputStream.writeBytes("Content-Type: application/octet-stream" + lineEnd);

                dataOutputStream.writeBytes(lineEnd);

                //returns no. of bytes present in fileInputStream
                bytesAvailable = fileInputStream.available();
                //selecting the buffer size as minimum of available bytes or 1 MB
                bufferSize = Math.min(bytesAvailable, maxBufferSize);
                //setting the buffer as byte array of size of bufferSize
                buffer = new byte[bufferSize];

                //reads bytes from FileInputStream(from 0th index of buffer to buffersize)
                bytesRead = fileInputStream.read(buffer, 0, bufferSize);

                //loop repeats till bytesRead = -1, i.e., no bytes are left to read
                while (bytesRead > 0) {
                    //write the bytes read from inputstream
                    dataOutputStream.write(buffer, 0, bufferSize);
                    bytesAvailable = fileInputStream.available();
                    bufferSize = Math.min(bytesAvailable, maxBufferSize);
                    bytesRead = fileInputStream.read(buffer, 0, bufferSize);
                }

                dataOutputStream.writeBytes(lineEnd);

                dataOutputStream.writeBytes(twoHyphens + boundary + lineEnd);
                dataOutputStream.writeBytes("Content-Disposition: form-data; name=\"submit\"" + lineEnd);
                dataOutputStream.writeBytes(lineEnd);
                dataOutputStream.writeBytes("Upload Image");

                dataOutputStream.writeBytes(lineEnd);
                dataOutputStream.writeBytes(twoHyphens + boundary + twoHyphens + lineEnd);

                serverResponseCode = connection.getResponseCode();
                String serverResponseMessage = connection.getResponseMessage();

                Log.i(TAG, "Server Response is: " + serverResponseMessage + ": " + serverResponseCode);

                //response code of 200 indicates the server status OK
                if (serverResponseCode == 200) {
                    Log.i(TAG, "File Upload completed.\n\n");
                }

                //closing the input and output streams
                fileInputStream.close();
                dataOutputStream.flush();
                dataOutputStream.close();


            } catch (FileNotFoundException e) {
                e.printStackTrace();
                Log.e(TAG, "File Not Found");
            } catch (MalformedURLException e) {
                e.printStackTrace();
                Toast.makeText(MainActivity.this, "URL error!", Toast.LENGTH_SHORT).show();

            } catch (IOException e) {
                e.printStackTrace();
                Toast.makeText(MainActivity.this, "Cannot Read/Write File!", Toast.LENGTH_SHORT).show();
            } catch (Throwable t) {
                System.out.println(t);
                t.printStackTrace();
                Toast.makeText(MainActivity.this, "Nejde to", Toast.LENGTH_LONG);
            }

            return serverResponseCode;
        }

    }

    private void downloadCert() {
        try {
            HttpURLConnection connection;
            URL url = new URL(baseURL + "/cert.pem");
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.connect();
            if (connection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                throw new Exception(connection.getResponseCode() + " " + connection.getResponseMessage());
            }

            FileOutputStream fos = openFileOutput("cert.pem", Context.MODE_PRIVATE);
            InputStream is = connection.getInputStream();
            byte[] buffer = new byte[1024];
            int len = 0;
            while ((len = is.read(buffer)) != -1) {
                fos.write(buffer, 0, len);
            }
            fos.close();
            is.close();

            this.runOnUiThread(new Runnable() {
                public void run() {
                    Toast.makeText(getBaseContext(), "Certifikát stažen", Toast.LENGTH_LONG).show();
                    Log.i(TAG, "Certifikat stazen");
                }
            });
        } catch (final Exception e) {
            e.printStackTrace();
            Log.e(TAG, e.getMessage());
            this.runOnUiThread(new Runnable() {
                public void run() {
                    Toast.makeText(getBaseContext(), "Certifikát nelze stáhnout: " + e.getMessage(), Toast.LENGTH_LONG).show();
                }
            });

        }
    }

}

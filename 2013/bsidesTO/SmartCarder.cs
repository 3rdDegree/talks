using System;
using System.Collections;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography.X509Certificates;
using eToken;
using System.Text;

namespace Smartcarder
{
    class Program
    {
        private static string FILE_PATH = @"card_info.dat";

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Usage();
            }
            else if (args.Length < 3)
            {
                if (args[0] == "/?" || args[0] == "/help")
                {
                    Usage();
                }

                else if (args[0].ToLower() == "/dump")
                {
                    if (args.Length > 1) { FILE_PATH = args[1]; }

                    DumpCardDataObjects();
                }

                else if (args[0].ToLower() == "/restore")
                {
                    if (args.Length > 1) { FILE_PATH = args[1]; }

                    WriteCardDataObjects();
                }

                else
                {
                    Usage();
                }
            }
            else
            {
                Usage();
            }
            
        }

        static void DumpCardDataObjects()
        {
            PKCS11.Initialize("etoken.dll");
            PKCS11.Slot[] slots = PKCS11.GetSlotList(true);
            if (slots.Length > 0)
            {
                PKCS11.Slot slot = slots[0];
                PKCS11.Session session = PKCS11.OpenSession(slot,
                  PKCS11.CKF_RW_SESSION | PKCS11.CKF_SERIAL_SESSION);

                int loginResult = session.Login(PKCS11.CKU_USER, null);

                if (loginResult == PKCS11.CKR_OK || loginResult == PKCS11.CKR_USER_ALREADY_LOGGED_IN)
                {
                    Console.WriteLine("PIN was correct");
                    PKCS11.Object[] dataObjects = session.FindObjects(new PKCS11.Attribute[]  {
                        new PKCS11.Attribute(PKCS11.CKA_TOKEN, true),
                        new PKCS11.Attribute(PKCS11.CKA_CLASS, PKCS11.CKO_DATA),
                    });

                    DataObjectStore dataObjectStore = new DataObjectStore();

                    Console.WriteLine("\nDump Data Objects");
                    Console.WriteLine("------------------------------------------------------------");
                    foreach (PKCS11.Object dataObject in dataObjects)
                    {
                        DataObject persistData = new DataObject();
                        persistData.cka_class = (int)dataObject.Get(session, PKCS11.CKA_CLASS);
                        persistData.cka_token = (bool)dataObject.Get(session, PKCS11.CKA_TOKEN);
                        persistData.cka_private = (bool)dataObject.Get(session, PKCS11.CKA_PRIVATE);
                        persistData.cka_label = (string)dataObject.Get(session, PKCS11.CKA_LABEL);

                        try { persistData.cka_application = (string)dataObject.Get(session, PKCS11.CKA_APPLICATION); }
                        catch (Exception e) { persistData.cka_application = ""; }

                        try { persistData.cka_value = ByteArrayToHex((byte[])dataObject.Get(session, PKCS11.CKA_VALUE)); }
                        catch (Exception e) { persistData.cka_value = ""; }

                        Console.WriteLine("CKA_CLASS:       " + persistData.cka_class);
                        Console.WriteLine("CKA_TOKEN:       " + persistData.cka_token);
                        Console.WriteLine("CKA_PRIVATE:     " + persistData.cka_private);
                        Console.WriteLine("CKA_LABEL:       " + persistData.cka_label);
                        Console.WriteLine("CKA_APPLICATION: " + persistData.cka_application);
                        Console.WriteLine("CKA_VALUE:       " + (persistData.cka_value.Length >= 40 ? persistData.cka_value.Substring(0, 40) + "..." : persistData.cka_value) + "\n");

                        dataObjectStore.objects.Add(persistData);
                    }
                    BackupDataObjects(dataObjectStore);
                }
                else
                {
                    Console.WriteLine("PIN was not correct");
                }

                session.Close();
                PKCS11.Finalize();
            }
            else
            {
                Console.WriteLine("Please connect a token and try again.");
            }
        }

        static void BackupDataObjects(DataObjectStore dataObjectStore)
        {
            Stream fileStream = File.Create(FILE_PATH);
            BinaryFormatter serializer = new BinaryFormatter();
            serializer.Serialize(fileStream, dataObjectStore);
            fileStream.Close();

            Console.WriteLine("Smartcard backed up to " + FILE_PATH);
        }

        static DataObjectStore RestoreDataObjects()
        {
            DataObjectStore loadedObjects;

            Stream fileStream = File.OpenRead(FILE_PATH);
            BinaryFormatter deserializer = new BinaryFormatter();
            loadedObjects = (DataObjectStore)deserializer.Deserialize(fileStream);
            fileStream.Close();

            Console.WriteLine("Smartcard data restored from " + FILE_PATH + "\n");
            return loadedObjects;
        }

        static void WriteCardDataObjects()
        {
            DataObjectStore dataObjectStore = RestoreDataObjects();

            PKCS11.Initialize("etoken.dll");
            PKCS11.Slot[] slots = PKCS11.GetSlotList(true);
            if (slots.Length > 0)
            {
                PKCS11.Slot slot = slots[0];
                PKCS11.Session session = PKCS11.OpenSession(slot,
                  PKCS11.CKF_RW_SESSION | PKCS11.CKF_SERIAL_SESSION);

                int loginResult = session.Login(PKCS11.CKU_USER, null);

                if (loginResult == PKCS11.CKR_OK || loginResult == PKCS11.CKR_USER_ALREADY_LOGGED_IN)
                {
                    Console.WriteLine("PIN was correct");                  

                    Console.WriteLine("\nWriting Data Objects");
                    Console.WriteLine("------------------------------------------------------------");
                    foreach (DataObject dataObject in dataObjectStore.objects)
                    {
                        PKCS11.Attribute[] newDataObject = new PKCS11.Attribute[]  {
                            new PKCS11.Attribute(PKCS11.CKA_CLASS, dataObject.cka_class),
                            new PKCS11.Attribute(PKCS11.CKA_TOKEN, dataObject.cka_token),
                            new PKCS11.Attribute(PKCS11.CKA_PRIVATE, dataObject.cka_private),
                            new PKCS11.Attribute(PKCS11.CKA_LABEL, dataObject.cka_label),
                            new PKCS11.Attribute(PKCS11.CKA_APPLICATION, dataObject.cka_application),
                            new PKCS11.Attribute(PKCS11.CKA_VALUE, StringToByteArray(dataObject.cka_value)),
                            
                        };
                        
                        PKCS11.Object.Create(session, newDataObject);

                        Console.WriteLine(dataObject.cka_label + ": " + (dataObject.cka_value.Length >= 40 ? dataObject.cka_value.Substring(0, 40) + "..." : dataObject.cka_value));
                    }
                }
                else
                {
                    Console.WriteLine("PIN was not correct");
                }

                session.Close();
                PKCS11.Finalize();
            }
            else
            {
                Console.WriteLine("Please connect a token and try again.");
            }
        }

        static void Usage()
        {
            Console.WriteLine("\nSmartcarder.exe - Read/Write data objects on a smartcard");
            Console.WriteLine("");
            Console.WriteLine("Usage:   Smartcarder.exe [OPTIONS]");
            Console.WriteLine("Options: ");
            Console.WriteLine("         /? | /help        Print this help screen");
            Console.WriteLine("         /dump [file]      Write smartcard data objects to file");
            Console.WriteLine("         /restore [file]   Write contents of file to smartcard\n");
        }

        static string ByteArrayToHex(byte[] data)
        {
            StringBuilder ret = new StringBuilder(data.Length * 2);

            foreach (byte b in data)
            {
                ret.AppendFormat("{0:x2}", b);
            }

            return ret.ToString();
        }

        static string ByteArrayToString(byte[] data)
        {
            string ret = "";

            foreach (byte b in data)
            {
                ret += (char)b;
            }

            return ret;
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}

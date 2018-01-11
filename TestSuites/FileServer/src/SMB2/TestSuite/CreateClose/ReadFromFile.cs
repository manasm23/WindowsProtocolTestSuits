using Microsoft.Protocols.TestSuites.FileSharing.Common.Adapter;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.Protocols.TestTools.StackSdk.Security.Sspi;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Net;
using System.Threading.Tasks;

namespace Microsoft.Protocols.TestSuites.FileSharing.SMB2.TestSuite.CreateClose
{
    [TestClass]
    public class ReadFromFile : SMB2TestBase
    {
        #region Fields
        private string fileName;
        private Smb2FunctionalClient client;        
        private FILEID fileId1;
        private const int DEFAULT_WRITE_BUFFER_SIZE_IN_KB = 1048576;
        protected ulong sessionId;
        #endregion

        #region Test Initialize and Cleanup
        [ClassInitialize()]
        public static void ClassInitialize(TestContext testContext)
        {
            TestClassBase.Initialize(testContext);
        }

        [ClassCleanup()]
        public static void ClassCleanup()
        {
            TestClassBase.Cleanup();
        }
        #endregion

        /// <summary>
        /// The client connects to the given IP addresses 
        /// Negotiate, SessionSetup, TreeConnect
        /// </summary>
        private Smb2FunctionalClient InitializeClient(IPAddress ip, out uint treeId)
        {
            client = new Smb2FunctionalClient(TestConfig.Timeout, TestConfig, this.Site);
            client.ConnectToServerOverTCP(ip);
            client.Negotiate(
                Smb2Utility.GetDialects(DialectRevision.Smb21),
                testConfig.IsSMB1NegotiateEnabled);

            AccountCredential accountCredential = false ? TestConfig.NonAdminAccountCredential : TestConfig.AccountCredential;
            client.SessionSetup(TestConfig.DefaultSecurityPackage, TestConfig.SutComputerName, accountCredential, false);

            string sharePath = Smb2Utility.GetUncPath(TestConfig.SutComputerName, TestConfig.BasicFileShare);
            client.TreeConnect(sharePath, out treeId);

            return client;
        }

        [TestMethod]
        [TestCategory(TestCategories.Bvt)]
        [TestCategory(TestCategories.Smb2002)]
        [TestCategory(TestCategories.CreateClose)]
        public void Read_Data_From_File()
        {
            uint treeId;
            client = InitializeClient(TestConfig.SutIPAddress, out treeId);
            
            //fileName = "NewFile.pdf";
            fileName = "NewFile3.pdf";

            Smb2CreateContextResponse[] contexts;
            
            client.Create(
                        treeId,
                        fileName,
                         CreateOptions_Values.FILE_SEQUENTIAL_ONLY | CreateOptions_Values.FILE_NON_DIRECTORY_FILE | CreateOptions_Values.FILE_OPEN_REPARSE_POINT,
                        out fileId1,
                        out contexts,
                        RequestedOplockLevel_Values.OPLOCK_LEVEL_LEASE);

            //byte[] data;
            uint defaultBufferSize = DEFAULT_WRITE_BUFFER_SIZE_IN_KB;
            ulong ulFileSize = 26795325;//8407754; //69903725;  //4615306; //26795325
            ulong uiByteRemaining = ulFileSize;
            ulong ulFileOffset = 0; 

            //Task<ulong> t1 = null;
            //Task t2 = null;

            do
            {
                defaultBufferSize = (uiByteRemaining < 1048576) ? (uint)uiByteRemaining : 1048576;

                //client.Read(treeId, fileId1, ulFileOffset, defaultBufferSize, out data);               

                Task<ulong> t1 = Task<ulong>.Factory.StartNew(() => client.ReadRequest(treeId, fileId1, ulFileOffset, defaultBufferSize));
                //ulong messageId = client.ReadRequest(treeId, fileId1, ulFileOffset, defaultBufferSize);

                t1.Wait();

                ulFileOffset += defaultBufferSize;
                uiByteRemaining -= defaultBufferSize;                

                //Task t2 = Task.Factory.StartNew(() => client.ReadResponse(t1.Result));
                client.ReadResponse(t1.Result);


                //Task<ulong> t2 = Task<ulong>.Factory.StartNew(() => client.ReadRequest(treeId, fileId1, ulFileOffset, defaultBufferSize));
                ////ulong messageId = client.ReadRequest(treeId, fileId1, ulFileOffset, defaultBufferSize);

                //t2.Wait();

                //ulFileOffset += defaultBufferSize;
                //uiByteRemaining -= defaultBufferSize;

                ////Task t2 = Task.Factory.StartNew(() => client.ReadResponse(t1.Result));
                //client.ReadResponse(t2.Result);


                //client.ReadResponse(messageId);
                //t2.Wait();
            }
            while (ulFileOffset < ulFileSize);

            client.Close(treeId, fileId1);
            
            AccountCredential accountCredential = false ? TestConfig.NonAdminAccountCredential : TestConfig.AccountCredential;            
            client.SessionSetup(TestConfig.DefaultSecurityPackage, TestConfig.SutComputerName, accountCredential, false);

            string sharePath = Smb2Utility.GetUncPath(TestConfig.SutComputerName, TestConfig.BasicFileShare);
            client.TreeConnect(sharePath, out treeId);

            //fileName = "TestFile.wrf";

            client.Create(
                        treeId,
                        fileName,
                         CreateOptions_Values.FILE_SEQUENTIAL_ONLY | CreateOptions_Values.FILE_NON_DIRECTORY_FILE | CreateOptions_Values.FILE_OPEN_REPARSE_POINT,
                        out fileId1,
                        out contexts,
                        RequestedOplockLevel_Values.OPLOCK_LEVEL_LEASE);

            //data = null;
            //defaultBufferSize = DEFAULT_WRITE_BUFFER_SIZE_IN_KB;
            //ulFileSize = 4615306; //69903725;
            uiByteRemaining = ulFileSize;
            ulFileOffset = 0;

            do
            {
                defaultBufferSize = (uiByteRemaining < 1048576) ? (uint)uiByteRemaining : 1048576;

                //client.Read(treeId, fileId1, ulFileOffset, defaultBufferSize, out data);               

                Task<ulong> t1 = Task<ulong>.Factory.StartNew(() => client.ReadRequest(treeId, fileId1, ulFileOffset, defaultBufferSize));
                //ulong messageId = client.ReadRequest(treeId, fileId1, ulFileOffset, defaultBufferSize);

                t1.Wait();

                ulFileOffset += defaultBufferSize;
                uiByteRemaining -= defaultBufferSize;

                //Task t2 = Task.Factory.StartNew(() => client.ReadResponse(t1.Result));
                client.ReadResponse(t1.Result);


                //Task<ulong> t2 = Task<ulong>.Factory.StartNew(() => client.ReadRequest(treeId, fileId1, ulFileOffset, defaultBufferSize));
                ////ulong messageId = client.ReadRequest(treeId, fileId1, ulFileOffset, defaultBufferSize);

                //t2.Wait();

                //ulFileOffset += defaultBufferSize;
                //uiByteRemaining -= defaultBufferSize;

                ////Task t2 = Task.Factory.StartNew(() => client.ReadResponse(t1.Result));
                //client.ReadResponse(t2.Result);


                //client.ReadResponse(messageId);
                //t2.Wait();
            }
            while (ulFileOffset < ulFileSize);
            
            client.Close(treeId, fileId1);

            client.LogOffSession();

            client.Disconnect();            
        }
    }
}

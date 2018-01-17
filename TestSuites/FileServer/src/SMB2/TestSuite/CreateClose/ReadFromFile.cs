using Microsoft.Protocols.TestSuites.FileSharing.Common.Adapter;
using Microsoft.Protocols.TestTools;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.Protocols.TestTools.StackSdk.Security.Sspi;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

namespace Microsoft.Protocols.TestSuites.FileSharing.SMB2.TestSuite.CreateClose
{
    [TestClass]
    public class ReadFromFile : SMB2TestBase
    {
        #region Fields
        private string fileName;
        private FILEID fileId1;
        private const int DEFAULT_WRITE_BUFFER_SIZE_IN_KB = 1048576;
        protected ulong sessionId;

        int noOfSessions = 0;

        uint treeId;
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
            Smb2FunctionalClient client = new Smb2FunctionalClient(TestConfig.Timeout, TestConfig, this.Site, ip);

            client.CloseCalledEvent += Client_CloseCalledEvent;

            AccountCredential accountCredential = false ? TestConfig.NonAdminAccountCredential : TestConfig.AccountCredential;
            client.SessionSetup(TestConfig.DefaultSecurityPackage, TestConfig.SutComputerName, accountCredential, false);

            string sharePath = Smb2Utility.GetUncPath(TestConfig.SutComputerName, TestConfig.BasicFileShare);
            client.TreeConnect(sharePath, out treeId);

            return client;
        }

        private void Client_CloseCalledEvent(Smb2FunctionalClient client)
        {
            noOfSessions--;

            if (noOfSessions == 0)
            {
                client.LogOffSession();

                client.Disconnect();
            }
        }

        [TestMethod]
        [TestCategory(TestCategories.Bvt)]
        [TestCategory(TestCategories.Smb2002)]
        [TestCategory(TestCategories.CreateClose)]
        public void Read_Data_From_File()
        {           
            noOfSessions = TestConfig.NoOfSessions;
            //var intLoopCount = TestConfig.NoOfSessions;

            for (int i = 0; i < TestConfig.NoOfSessions; i++)
            {
                var client = InitializeClient(TestConfig.SutIPAddress, out treeId);
               
                fileName = "NewFile.pdf";
                //fileName = "NewFile3.pdf";
                //fileName = "NewFile2.pptx";

                Smb2CreateContextResponse[] contexts;

                client.Create(
                            treeId,
                            fileName,
                             CreateOptions_Values.FILE_SEQUENTIAL_ONLY | CreateOptions_Values.FILE_NON_DIRECTORY_FILE | CreateOptions_Values.FILE_OPEN_REPARSE_POINT,
                            out fileId1,
                            out contexts,
                            RequestedOplockLevel_Values.OPLOCK_LEVEL_LEASE);

                //byte[] data;
                ReadDataFromFile(client);                
            }
        }        

        private void ReadDataFromFile(Smb2FunctionalClient client)
        {
            uint defaultBufferSize = DEFAULT_WRITE_BUFFER_SIZE_IN_KB;
            ulong ulFileSize = 4615306;//8407754; //69903725;  //4615306; //26795325
            ulong uiByteRemaining = ulFileSize;
            ulong ulFileOffset = 0;

            ulong extraPacket = ((0 == ulFileSize % defaultBufferSize) ? (ulong)0 : 1);
            client.noOfRequest = (ulFileSize / defaultBufferSize) + extraPacket;
           
            List<ulong> messageIdsList = new List<ulong>();

            do
            {
                defaultBufferSize = (uiByteRemaining < 1048576) ? (uint)uiByteRemaining : 1048576;                        

                Task<ulong> t1 = Task<ulong>.Factory.StartNew(() => client.ReadRequest(treeId, fileId1, ulFileOffset, defaultBufferSize));
                
                //This wait is done to make sure the first offset read is not missed
                t1.Wait();

                ulFileOffset += defaultBufferSize;
                uiByteRemaining -= defaultBufferSize;
                
                messageIdsList.Add(t1.Result);

                ///Uncomment the below code if you need to send request in bulk of 4 and then process their resposne
                //if (messageIdsList.Count % 4 == 0 || ulFileOffset == ulFileSize)
                //{
                //    foreach (ulong messageId in messageIdsList)
                //    {
                //        client.ReadResponse(messageId);
                //    }

                //    messageIdsList.Clear();
                //}                
            }
            while (ulFileOffset < ulFileSize);

            ///Comment the below code if you wish to use the Bulk request Read option
            //Read responses from the server
            foreach (ulong messageId in messageIdsList)
            {
                client.ReadResponse(messageId);
            }
        }        
    }
}

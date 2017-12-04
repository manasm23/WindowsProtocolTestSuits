using Microsoft.Protocols.TestSuites.FileSharing.Common.Adapter;
using Microsoft.Protocols.TestTools.StackSdk.FileAccessService.Smb2;
using Microsoft.Protocols.TestTools.StackSdk.Security.Sspi;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using Microsoft.Protocols.TestTools;
using System.IO;

namespace Microsoft.Protocols.TestSuites.FileSharing.SMB2.TestSuite.CreateClose
{
    [TestClass]
    public class WriteToFile : SMB2TestBase
    {
        #region Fields
        private string fileName;
        private const int DEFAULT_WRITE_BUFFER_SIZE_IN_KB = 1;
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
        /// The two client connects to the two IP addresses of scaleout file server
        /// Negotiate, SessionSetup, TreeConnect
        /// </summary>
        private Smb2FunctionalClient InitializeClient(IPAddress ip, out uint treeId)
        {
            Smb2FunctionalClient client = new Smb2FunctionalClient(TestConfig.Timeout, TestConfig, this.Site);
            client.ConnectToServerOverTCP(ip);
            client.Negotiate(
                Smb2Utility.GetDialects(DialectRevision.Smb21),
                testConfig.IsSMB1NegotiateEnabled);
            //client.SessionSetup(
            //    testConfig.DefaultSecurityPackage,
            //    //testConfig.ScaleOutFileServerName,
            //    testConfig.AccountCredential,
            //    testConfig.UseServerGssToken);
            AccountCredential accountCredential = false ? TestConfig.NonAdminAccountCredential : TestConfig.AccountCredential;
            client.SessionSetup(TestConfig.DefaultSecurityPackage, TestConfig.SutComputerName, accountCredential, false);
            //client.TreeConnect(Smb2Utility.GetUncPath(testConfig.ScaleOutFileServerName, testConfig.CAShareName), out treeId);

            //uint treeId_t;
            string sharePath = Smb2Utility.GetUncPath(TestConfig.SutComputerName, TestConfig.BasicFileShare);
            client.TreeConnect(sharePath, out treeId);

            return client;
        }

        [TestMethod]
        [TestCategory(TestCategories.Bvt)]
        [TestCategory(TestCategories.Smb2002)]
        [TestCategory(TestCategories.CreateClose)]
        public void Write_Data_To_File()
        {
            uint treeId;
            try
            {
                Smb2FunctionalClient client = InitializeClient(TestConfig.SutIPAddress, out treeId);

                // Initialize file name
                fileName = "ConflictModel_" + Guid.NewGuid() + ".txt";
                FILEID fileId;
                Smb2CreateContextResponse[] contexts;
                
                client.Create(
                    treeId,
                    fileName,
                    CreateOptions_Values.FILE_NON_DIRECTORY_FILE,
                    out fileId,
                    out contexts);
                //client.Write(treeId, fileId, Smb2Utility.CreateRandomString(DEFAULT_WRITE_BUFFER_SIZE_IN_KB));
                
                client.Write(treeId, fileId, "this is a random string");
                client.Write(treeId, fileId, "this is a random string2");

                client.Close(treeId, fileId);
                
                client.LogOff();
                
                client.Disconnect();
                
            }
            catch (Exception ex)
            {
                File.AppendAllText(@"C:\Code\error.txt", ex.Message);
                File.AppendAllText(@"C:\Code\error.txt", ex.StackTrace);
                //throw;
            }




        }
    }
}

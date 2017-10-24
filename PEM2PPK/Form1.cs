using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows.Forms;

namespace PEM2PPK
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            AllowDrop = true; //D&D許可
            DragDrop += new DragEventHandler(Form1_DragDrop);
            DragEnter += new DragEventHandler(Form1_DragEnter);
            //大きさ固定
            this.FormBorderStyle = FormBorderStyle.FixedSingle;
            //フォームが最大化されないようにする
            this.MaximizeBox = false;
            //フォームが最小化されないようにする
            this.MinimizeBox = false;
        }
        private void Form1_DragEnter(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
                e.Effect = DragDropEffects.Copy;
            else
                e.Effect = DragDropEffects.None;
        }
        private void Form1_DragDrop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                try
                {
                    //https://stackoverflow.com/questions/46103923/c-sharp-bouncy-castle-decoding-private-key より
                    StreamReader sr = new StreamReader(files[0]);
                    PemReader pr = new PemReader(sr);
                    AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
                    RSAParameters rsa =
                            DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);
                    //PPKに変換
                    var ppk = PuttyKeyFileGenerator.RSAToPuttyPrivateKey(rsa);
                    //ダイアログ表示
                    //SaveFileDialogクラスのインスタンスを作成
                    SaveFileDialog sfd = new SaveFileDialog();

                    //はじめのファイル名を指定する
                    //はじめに「ファイル名」で表示される文字列を指定する
                    sfd.FileName = files[0] + ".ppk";
                    //はじめに表示されるフォルダを指定する
                    sfd.InitialDirectory = @"C:\";
                    //[ファイルの種類]に表示される選択肢を指定する
                    //指定しない（空の文字列）の時は、現在のディレクトリが表示される
                    sfd.Filter = "PPKファイル(*.ppk)|*.ppk";
                    //[ファイルの種類]ではじめに選択されるものを指定する
                    //タイトルを設定する
                    sfd.Title = "保存先のファイルを選択してください";
                    //ダイアログボックスを閉じる前に現在のディレクトリを復元するようにする
                    sfd.RestoreDirectory = true;
                    //既に存在するファイル名を指定したとき警告する
                    //デフォルトでTrueなので指定する必要はない
                    sfd.OverwritePrompt = true;
                    //存在しないパスが指定されたとき警告を表示する
                    //デフォルトでTrueなので指定する必要はない
                    sfd.CheckPathExists = true;

                    //ダイアログを表示する
                    if (sfd.ShowDialog() == DialogResult.OK)
                    {
                        //OKボタンがクリックされたとき、選択されたファイル名を表示する
                        //ファイル削除し保存する。
                        File.Delete(sfd.FileName);
                        File.WriteAllText(sfd.FileName, ppk);

                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("変換できません！！");
                    return;
                }
            }
        }

    }
}

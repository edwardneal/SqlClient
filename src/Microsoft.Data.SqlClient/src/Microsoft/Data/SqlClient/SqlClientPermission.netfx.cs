// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if NETFRAMEWORK

using System;
using System.Collections;
using System.Data;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Reflection;
using System.Security;
using System.Security.Permissions;
using Microsoft.Data.Common;
using DBDataPermission = System.Data.Common.DBDataPermission;

namespace Microsoft.Data.SqlClient
{
    /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientPermission.xml' path='docs/members[@name="SqlClientPermission"]/SqlClientPermission/*' />
    [Serializable]
    public sealed class SqlClientPermission : DBDataPermission
    {
        #region Member Variables
        
        // @TODO: Replace ArrayList with a typed list.
        private NameValuePermission _keyvaluetree = NameValuePermission.Default;
        private ArrayList _keyvalues;
        
        #endregion
        
        #region Constructors
        
        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientPermission.xml' path='docs/members[@name="SqlClientPermission"]/ctor[@name="default"]/*' />
        [Obsolete("SqlClientPermission() has been deprecated.  Use the SqlClientPermission(PermissionState.None) constructor.  http://go.microsoft.com/fwlink/?linkid=14202", true)] // MDAC 86034
        public SqlClientPermission() : this(PermissionState.None)
        {
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientPermission.xml' path='docs/members[@name="SqlClientPermission"]/ctor[@name="PermissionState"]/*' />
        public SqlClientPermission(PermissionState state) : base(state)
        {
        }

        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientPermission.xml' path='docs/members[@name="SqlClientPermission"]/ctor[@name="PermissionStateAndallowBlankPasswordBool"]/*' />
        [Obsolete("SqlClientPermission(PermissionState state, Boolean allowBlankPassword) has been deprecated.  Use the SqlClientPermission(PermissionState.None) constructor.  http://go.microsoft.com/fwlink/?linkid=14202", true)] // MDAC 86034
        public SqlClientPermission(PermissionState state, bool allowBlankPassword) : this(state)
        {
            AllowBlankPassword = allowBlankPassword;
        }

        internal SqlClientPermission(SqlClientPermissionAttribute permissionAttribute) : base(permissionAttribute)
        {
            // Used by SqlClientPermissionAttribute.CreatePermission
        }

        internal SqlClientPermission(SqlConnectionString constr) : base(PermissionState.None)
        {
            // Used by SqlConnectionString.CreatePermissionSet
            
            if (constr != null)
            {
                AllowBlankPassword = constr.HasBlankPassword; // MDAC 84563
                AddPermissionEntry(new DbConnectionString(constr));
            }
            
            if (constr == null || constr.IsEmpty)
            {
                base.Add("", "", KeyRestrictionBehavior.AllowOnly);
            }
        }
        
        private SqlClientPermission(SqlClientPermission permission) : base(permission)
        { 
            // for Copy
            // Explicitly copyFrom to clone the key value pairs
            CopyFrom(permission);
        }
        
        #endregion
        
        #region Properties
        
        private bool _IsUnrestricted
        {
            get
            {
                return base.IsUnrestricted();
            }
            
            set
            {
                // Use Reflection to access the base class _isUnrestricted. There is no other way to alter this externally.
                FieldInfo fieldInfo = GetType().BaseType.GetField(
                    "_isUnrestricted",
                    BindingFlags.Instance | BindingFlags.NonPublic);
                fieldInfo.SetValue(this, value);
            }
        }
        
        #endregion

        #region Public/Internal Methods
        
        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientPermission.xml' path='docs/members[@name="SqlClientPermission"]/Add[@name="connectionStringAndrestrictionsStringAndBehavior"]/*' />
        public override void Add(string connectionString, string restrictions, KeyRestrictionBehavior behavior)
        {
            DbConnectionString constr = new DbConnectionString(connectionString, restrictions, behavior, SqlConnectionString.GetParseSynonyms(), false);
            AddPermissionEntry(constr);
        }
        
        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientPermission.xml' path='docs/members[@name="SqlClientPermission"]/Copy/*' />
        public override IPermission Copy()
        {
            return new SqlClientPermission(this);
        }
        
        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientPermission.xml' path='docs/members[@name="SqlClientPermission"]/FromXml/*' />
        public override void FromXml(SecurityElement securityElement)
        {
            // Reads an XML tree like:
            // <IPermission class="...Permission" version="1" AllowBlankPassword=false>
            //     <add ConnectionString="provider=x;data source=y;" KeyRestrictions="address=;server=" KeyRestrictionBehavior=PreventUsage/>
            // </IPermission>
            
            // code derived from CodeAccessPermission.ValidateElement
            if (securityElement == null)
            {
                throw ADP.ArgumentNull("securityElement");
            }
            
            string tag = securityElement.Tag;
            if (!tag.Equals(XmlStr._Permission) && !tag.Equals(XmlStr._IPermission))
            {
                throw ADP.NotAPermissionElement();
            }
            
            string version = securityElement.Attribute(XmlStr._Version);
            if (version != null && !version.Equals(XmlStr._VersionNumber))
            {
                throw ADP.InvalidXMLBadVersion();
            }

            string unrestrictedValue = securityElement.Attribute(XmlStr._Unrestricted);
            _IsUnrestricted = unrestrictedValue != null && bool.Parse(unrestrictedValue);

            Clear(); // MDAC 83105
            if (!_IsUnrestricted)
            {
                string allowNull = securityElement.Attribute(XmlStr._AllowBlankPassword);
                AllowBlankPassword = allowNull != null && bool.Parse(allowNull);

                ArrayList children = securityElement.Children;
                if (children != null)
                {
                    foreach (SecurityElement keyElement in children)
                    {
                        tag = keyElement.Tag;
                        if (XmlStr._add == tag || (tag != null && XmlStr._add == tag.ToLower(CultureInfo.InvariantCulture)))
                        {
                            string constr = keyElement.Attribute(XmlStr._ConnectionString);
                            string restrt = keyElement.Attribute(XmlStr._KeyRestrictions);
                            string behavr = keyElement.Attribute(XmlStr._KeyRestrictionBehavior);

                            KeyRestrictionBehavior behavior = KeyRestrictionBehavior.AllowOnly;
                            if (behavr != null)
                            {
                                behavior = (KeyRestrictionBehavior)Enum.Parse(typeof(KeyRestrictionBehavior), behavr, true);
                            }
                            
                            constr = WebUtility.HtmlDecode(constr);
                            restrt = WebUtility.HtmlDecode(restrt);
                            Add(constr, restrt, behavior);
                        }
                    }
                }
            }
            else
            {
                AllowBlankPassword = false;
            }
        }
        
        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientPermission.xml' path='docs/members[@name="SqlClientPermission"]/Intersect/*' />
        public override IPermission Intersect(IPermission target)
        { 
            // used during Deny actions
            if (target == null)
            {
                return null;
            }
            if (target.GetType() != this.GetType())
            {
                throw ADP.PermissionTypeMismatch();
            }
            if (this.IsUnrestricted())
            { // MDAC 84803, NDPWhidbey 29121
                return target.Copy();
            }

            DBDataPermission operand = (DBDataPermission)target;
            if (operand.IsUnrestricted())
            { // NDPWhidbey 29121
                return this.Copy();
            }

            SqlClientPermission newPermission = (SqlClientPermission)operand.Copy();
            newPermission.AllowBlankPassword &= AllowBlankPassword;

            if (_keyvalues != null && newPermission._keyvalues != null)
            {
                newPermission._keyvalues.Clear();

                newPermission._keyvaluetree.Intersect(newPermission._keyvalues, _keyvaluetree);
            }
            else
            {
                // either target.Add or this.Add have not been called
                // return a non-null object so IsSubset calls will fail
                newPermission._keyvalues = null;
                newPermission._keyvaluetree = null;
            }

            if (newPermission.IsEmpty())
            { // no intersection, MDAC 86773
                newPermission = null;
            }
            return newPermission;
        }
        
        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientPermission.xml' path='docs/members[@name="SqlClientPermission"]/IsSubsetOf/*' />
        public override bool IsSubsetOf(IPermission target)
        {
            if (null == target)
            {
                return IsEmpty();
            }
            if (target.GetType() != this.GetType())
            {
                throw ADP.PermissionTypeMismatch();
            }

            SqlClientPermission superset = (target as SqlClientPermission);

            bool subset = superset.IsUnrestricted();
            if (!subset)
            {
                if (!IsUnrestricted() &&
                    (!AllowBlankPassword || superset.AllowBlankPassword) &&
                    (_keyvalues == null || superset._keyvaluetree != null))
                {

                    subset = true;
                    if (_keyvalues != null)
                    {
                        foreach (DbConnectionString kventry in _keyvalues)
                        {
                            if (!superset._keyvaluetree.CheckValueForKeyPermit(kventry))
                            {
                                subset = false;
                                break;
                            }
                        }
                    }
                }
            }
            return subset;
        }
        
        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientPermission.xml' path='docs/members[@name="SqlClientPermission"]/ToXml/*' />
        public override SecurityElement ToXml()
        {
            // Generates an XML tree like:
            // <IPermission class="...Permission" version="1" AllowBlankPassword=false>
            //     <add ConnectionString="provider=x;data source=y;"/>
            //     <add ConnectionString="provider=x;data source=y;" KeyRestrictions="user id=;password=;" KeyRestrictionBehavior=AllowOnly/>
            //     <add ConnectionString="provider=x;data source=y;" KeyRestrictions="address=;server=" KeyRestrictionBehavior=PreventUsage/>
            // </IPermission>
            
            Type type = GetType();
            SecurityElement root = new SecurityElement(XmlStr._IPermission);
            root.AddAttribute(XmlStr._class, type.AssemblyQualifiedName.Replace('\"', '\''));
            root.AddAttribute(XmlStr._Version, XmlStr._VersionNumber);

            if (IsUnrestricted())
            {
                root.AddAttribute(XmlStr._Unrestricted, XmlStr._true);
            }
            else
            {
                root.AddAttribute(XmlStr._AllowBlankPassword, AllowBlankPassword.ToString(CultureInfo.InvariantCulture));

                if (_keyvalues != null)
                {
                    foreach (DbConnectionString value in _keyvalues)
                    {
                        SecurityElement valueElement = new SecurityElement(XmlStr._add);
                        string tmp;

                        tmp = SecurityElement.Escape(value.ConnectionString);
                        if (!string.IsNullOrEmpty(tmp))
                        {
                            valueElement.AddAttribute(XmlStr._ConnectionString, tmp);
                        }
                        
                        tmp = SecurityElement.Escape(value.Restrictions) ?? "";
                        valueElement.AddAttribute(XmlStr._KeyRestrictions, tmp);

                        tmp = value.Behavior.ToString();
                        valueElement.AddAttribute(XmlStr._KeyRestrictionBehavior, tmp);

                        root.AddChild(valueElement);
                    }
                }
            }
            return root;
        }
        
        /// <include file='../../../../../../doc/snippets/Microsoft.Data.SqlClient/SqlClientPermission.xml' path='docs/members[@name="SqlClientPermission"]/Union/*' />
        public override IPermission Union(IPermission target)
        {
            if (target == null)
            {
                return Copy();
            }
            
            if (target.GetType() != GetType())
            {
                throw ADP.PermissionTypeMismatch();
            }
            
            if (IsUnrestricted())
            {
                return Copy();
            }

            SqlClientPermission newPermission = (SqlClientPermission)target.Copy();
            if (!newPermission.IsUnrestricted())
            {
                newPermission.AllowBlankPassword |= AllowBlankPassword;

                if (_keyvalues != null)
                {
                    foreach (DbConnectionString entry in _keyvalues)
                    {
                        newPermission.AddPermissionEntry(entry);
                    }
                }
            }
            
            return newPermission.IsEmpty() ? null : newPermission;
        }
        
        internal void AddPermissionEntry(DbConnectionString entry)
        {
            if (_keyvaluetree == null)
            {
                _keyvaluetree = new NameValuePermission();
            }
            
            if (_keyvalues == null)
            {
                _keyvalues = new ArrayList();
            }
            
            NameValuePermission.AddEntry(_keyvaluetree, _keyvalues, entry);
            _IsUnrestricted = false;
        }
        
        #endregion
        
        #region Private Methods
        
        // Modified CopyFrom to make sure that we copy the Name Value Pair
        private void CopyFrom(SqlClientPermission permission)
        {
            if (!_IsUnrestricted)
            {
                if (permission._keyvalues != null)
                {
                    _keyvalues = (ArrayList)permission._keyvalues.Clone();

                    if (permission._keyvaluetree != null)
                    {
                        _keyvaluetree = permission._keyvaluetree.CopyNameValue();
                    }
                }
            }
        }
        
        private bool IsEmpty()
        {
            ArrayList keyvalues = _keyvalues;
            bool flag = !IsUnrestricted() && !AllowBlankPassword && (keyvalues == null || (0 == keyvalues.Count));
            return flag;
        }
        
        #endregion

        [Serializable]
        private sealed class NameValuePermission : IComparable
        {
            // Reused as both key and value nodes:
            // Key nodes link to value nodes.
            // Value nodes link to key nodes.
            private readonly string _value;

            // value node with (_restrictions != null) are allowed to match connection strings
            private DbConnectionString _entry;

            private NameValuePermission[] _tree; // with branches

            internal static readonly NameValuePermission Default = null;

            internal NameValuePermission()
            { // root node
            }

            private NameValuePermission(NameValuePermission permit)
            { 
                // deep-copy
                _value = permit._value;
                _entry = permit._entry;
                _tree = permit._tree;
                if (_tree != null)
                {
                    NameValuePermission[] tree = _tree.Clone() as NameValuePermission[];
                    for (int i = 0; i < tree.Length; ++i)
                    {
                        if (tree[i] != null)
                        { // WebData 98488
                            tree[i] = tree[i].CopyNameValue(); // deep copy
                        }
                    }
                    _tree = tree;
                }
            }
            
            private NameValuePermission(string keyword)
            {
                _value = keyword;
            }

            private NameValuePermission(string value, DbConnectionString entry)
            {
                _value = value;
                _entry = entry;
            }

            int IComparable.CompareTo(object other) =>
                string.CompareOrdinal(_value, ((NameValuePermission)other)._value);

            internal static void AddEntry(NameValuePermission kvtree, ArrayList entries, DbConnectionString entry)
            {
                Debug.Assert(entry != null, "null DbConnectionString");

                if (entry.KeyChain != null)
                {
                    for (NameValuePair keychain = entry.KeyChain; keychain != null; keychain = keychain.Next)
                    {
                        NameValuePermission kv = kvtree.CheckKeyForValue(keychain.Name);
                        if (kv == null)
                        {
                            kv = new NameValuePermission(keychain.Name);
                            kvtree.Add(kv); // add directly into live tree
                        }
                        
                        kvtree = kv;

                        kv = kvtree.CheckKeyForValue(keychain.Value);
                        if (kv == null)
                        {
                            DbConnectionString insertValue = keychain.Next != null ? null : entry;
                            kv = new NameValuePermission(keychain.Value, insertValue);
                            kvtree.Add(kv); // add directly into live tree
                            if (insertValue != null)
                            {
                                entries.Add(insertValue);
                            }
                        }
                        else if (keychain.Next == null)
                        {
                            // shorter chain potential
                            if (kv._entry != null)
                            {
                                Debug.Assert(entries.Contains(kv._entry), "entries doesn't contain entry");
                                entries.Remove(kv._entry);
                                kv._entry = kv._entry.Intersect(entry); // union new restrictions into existing tree
                            }
                            else
                            {
                                kv._entry = entry;
                            }
                            entries.Add(kv._entry);
                        }
                        kvtree = kv;
                    }
                }
                else
                {
                    // global restrictions
                    DbConnectionString kentry = kvtree._entry;
                    if (kentry != null)
                    {
                        Debug.Assert(entries.Contains(kentry), "entries doesn't contain entry");
                        entries.Remove(kentry);
                        kvtree._entry = kentry.Intersect(entry);
                    }
                    else
                    {
                        kvtree._entry = entry;
                    }
                    
                    entries.Add(kvtree._entry);
                }
            }

            internal bool CheckValueForKeyPermit(DbConnectionString parsetable)
            {
                if (parsetable == null)
                {
                    return false;
                }
                
                bool hasMatch = false;
                NameValuePermission[] keytree = _tree; // _tree won't mutate but Add will replace it
                if (keytree != null)
                {
                    hasMatch = parsetable.IsEmpty; // MDAC 86773
                    if (!hasMatch)
                    {
                        // which key do we follow the key-value chain on
                        foreach (var permitKey in keytree)
                        {
                            if (permitKey != null)
                            {
                                string keyword = permitKey._value;
    
                                Debug.Assert(permitKey._entry == null, "key member has no restrictions");
                                if (parsetable.ContainsKey(keyword))
                                {
                                    string valueInQuestion = (string)parsetable[keyword];

                                    // keyword is restricted to certain values
                                    NameValuePermission permitValue = permitKey.CheckKeyForValue(valueInQuestion);
                                    if (permitValue != null)
                                    {
                                        //value does match - continue the chain down that branch
                                        if (permitValue.CheckValueForKeyPermit(parsetable))
                                        {
                                            hasMatch = true;
                                            // adding a break statement is tempting, but wrong
                                            // user can safely extend their restrictions for current rule to include missing keyword
                                            // i.e. Add("provider=sqloledb;integrated security=sspi", "data provider=", KeyRestrictionBehavior.AllowOnly);
                                            // i.e. Add("data provider=msdatashape;provider=sqloledb;integrated security=sspi", "", KeyRestrictionBehavior.AllowOnly);
                                        }
                                        else
                                        { // failed branch checking
                                            return false;
                                        }
                                    }
                                    else
                                    { // value doesn't match to expected values - fail here
                                        return false;
                                    }
                                }
                            }
                        }
                    }
                    // partial chain match, either leaf-node by shorter chain or fail mid-chain if ( _restrictions == null)
                }

                DbConnectionString entry = _entry;
                if (entry != null)
                {
                    // also checking !hasMatch is tempting, but wrong
                    // user can safely extend their restrictions for current rule to include missing keyword
                    // i.e. Add("provider=sqloledb;integrated security=sspi", "data provider=", KeyRestrictionBehavior.AllowOnly);
                    // i.e. Add("provider=sqloledb;", "integrated security=;", KeyRestrictionBehavior.AllowOnly);
                    hasMatch = entry.IsSupersetOf(parsetable);
                }

                // mid-chain failure
                return hasMatch;
            }

            internal NameValuePermission CopyNameValue()
            {
                return new NameValuePermission(this);
            }
            
            internal void Intersect(ArrayList entries, NameValuePermission target)
            {
                if (target == null)
                {
                    _tree = null;
                    _entry = null;
                }
                else
                {
                    if (_entry != null)
                    {
                        entries.Remove(_entry);
                        _entry = _entry.Intersect(target._entry);
                        entries.Add(_entry);
                    }
                    else if (target._entry != null)
                    {
                        _entry = target._entry.Intersect(null);
                        entries.Add(_entry);
                    }

                    if (_tree != null)
                    {
                        int count = _tree.Length;
                        for (int i = 0; i < _tree.Length; ++i)
                        {
                            NameValuePermission kvtree = target.CheckKeyForValue(_tree[i]._value);
                            if (kvtree != null)
                            { // does target tree contain our value
                                _tree[i].Intersect(entries, kvtree);
                            }
                            else
                            {
                                _tree[i] = null;
                                --count;
                            }
                        }
                        if (0 == count)
                        {
                            _tree = null;
                        }
                        else if (count < _tree.Length)
                        {
                            NameValuePermission[] kvtree = new NameValuePermission[count];
                            for (int i = 0, j = 0; i < _tree.Length; ++i)
                            {
                                if (_tree[i] != null)
                                {
                                    kvtree[j++] = _tree[i];
                                }
                            }
                            _tree = kvtree;
                        }
                    }
                }
            }
            
            private void Add(NameValuePermission permit)
            {
                NameValuePermission[] tree = _tree;
                int length = tree != null ? tree.Length : 0;
                NameValuePermission[] newtree = new NameValuePermission[1 + length];
                for (int i = 0; i < newtree.Length - 1; ++i)
                {
                    newtree[i] = tree[i];
                }
                newtree[length] = permit;
                Array.Sort(newtree);
                _tree = newtree;
            }
            
            private NameValuePermission CheckKeyForValue(string keyInQuestion)
            {
                NameValuePermission[] valuetree = _tree; // _tree won't mutate but Add will replace it
                if (valuetree != null)
                {
                    foreach (var permitValue in valuetree)
                    {
                        if (string.Equals(keyInQuestion, permitValue._value, StringComparison.OrdinalIgnoreCase))
                        {
                            return permitValue;
                        }
                    }
                }
                return null;
            }
        } 
        
        private static class XmlStr
        {
            internal const string _class = "class";
            internal const string _IPermission = "IPermission";
            internal const string _Permission = "Permission";
            internal const string _Unrestricted = "Unrestricted";
            internal const string _AllowBlankPassword = "AllowBlankPassword";
            internal const string _true = "true";
            internal const string _Version = "version";
            internal const string _VersionNumber = "1";

            internal const string _add = "add";

            internal const string _ConnectionString = "ConnectionString";
            internal const string _KeyRestrictions = "KeyRestrictions";
            internal const string _KeyRestrictionBehavior = "KeyRestrictionBehavior";
        }
    }
}

#endif

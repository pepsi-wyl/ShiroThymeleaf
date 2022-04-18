![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1649554582282-32d5e7e8-7feb-4f9c-a6e6-094d5cdd416d.png#clientId=u3562c086-199d-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=141&id=u363c239a&margin=%5Bobject%20Object%5D&name=image.png&originHeight=141&originWidth=1231&originalType=binary&ratio=1&rotation=0&showTitle=false&size=49266&status=done&style=none&taskId=u00d3a450-b2ff-47a2-a21d-df10897e161&title=&width=1231)
<a name="YDUPQ"></a>
# 简介
<a name="jkkAy"></a>
## 权限管理
涉及到用户参与的系统都要进行权限管理，权限管理属于系统安全的范畴，权限管理实现`对用户访问系统的控制`，按照`安全规则`或者`安全策略`控制用户`可以访问而且只能访问自己被授权的资源`。<br />权限管理包括用户**身份认证**和**授权**两部分，简称**认证授权**。<br />对于需要访问控制的资源用户首先经过身份认证，认证通过后用户具有该资源的访问权限方可访问。
<a name="zU0fh"></a>
### 认证
`**身份认证**`，就是判断一个用户是否为合法用户的处理过程<br />最常用的简单身份认证方式是系统通过核对用户输入的用户名和口令，看其是否与系统中存储的该用户的用户名和口令一致，来判断用户身份是否正确<br />对于采用[指纹](http://baike.baidu.com/view/5628.htm)等系统，则出示指纹；对于硬件Key等刷卡系统，则需要刷卡
<a name="uEahM"></a>
### 授权
`**授权**`，即访问控制，控制谁能访问哪些资源<br />主体进行身份认证后需要分配权限方可访问系统的资源，对于某些资源没有权限是无法访问的
<a name="S7nT3"></a>
## [Shiro](https://shiro.apache.org/)
![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1649554618521-83b4ddfb-288d-4bec-b32e-13489efdf505.png#clientId=u3562c086-199d-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=107&id=u45b1b62c&margin=%5Bobject%20Object%5D&name=image.png&originHeight=107&originWidth=783&originalType=binary&ratio=1&rotation=0&showTitle=false&size=17421&status=done&style=none&taskId=ue5e44491-7eb7-4acb-af2d-ea9dac64879&title=&width=783)
```markdown
Shiro 是一个功能强大且易于使用的Java安全框架，它执行身份验证、
授权、加密和会话管理。使用Shiro易于理解的API，您可以快速轻松地保
护任何应用程序—从最小的移动应用程序到最大的web和企业应用程序。
```
```markdown
Shiro 是apache旗下一个开源框架，它将软件系统的安全认证相关的功能
抽取出来，实现用户身份认证，权限授权、加密、会话管理等功能，组成
了一个通用的安全认证框架。
```

- 老牌的安全管理框架
- 轻量、简单、易于集成、可以在JavaSE环境中使用
- 在微服务面前和扩展方面，无法充分展示自己的优势 (Spring Security)
<a name="J4vs0"></a>
# 核心架构
![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1649555181317-6b43d37c-fb8b-4238-89fb-23f92a72b136.png#clientId=u3562c086-199d-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=462&id=ub3be350d&margin=%5Bobject%20Object%5D&name=image.png&originHeight=462&originWidth=611&originalType=binary&ratio=1&rotation=0&showTitle=false&size=149563&status=done&style=none&taskId=u468a8ece-a262-4552-81ac-a185080a7cf&title=&width=611)
<a name="KpluF"></a>
## Subject 主体
外部应用与subject进行交互，subject记录了当前操作用户，将用户的概念理解为当前操作的主体，可能是一个通过浏览器请求的用户，也可能是一个运行的程序。<br />Subject在shiro中是一个接口，接口中定义了很多认证授相关的方法，外部程序通过subject进行认证授，而subject是通过SecurityManager安全管理器进行认证授权
<a name="YGLCN"></a>
## SecurityManager 安全管理器
SecurityManager是一个接口<br />继承了Authenticator, Authorizer, SessionManager这三个接口。<br />对全部的subject进行安全管理，它是shiro的核心，负责对所有的subject进行安全管理。<br />通过SecurityManager可以完成subject的认证、授权等，实质上SecurityManager是通过Authenticator进行认证，通过Authorizer进行授权，通过SessionManager进行会话管理等。
<a name="lCG3y"></a>
## Authenticator 认证器
对用户身份进行认证<br />Authenticator是一个接口，shiro提供ModularRealmAuthenticator实现类，通过ModularRealmAuthenticator基本上可以满足大多数需求，也可以自定义认证器。
<a name="L2SdM"></a>
## Authorizer 授权器
用户通过认证器认证通过，在访问功能时需要通过授权器判断用户是否有此功能的操作权限。
<a name="VN9gg"></a>
## Realm 领域
相当于datasource数据源，securityManager进行安全认证需要通过Realm获取用户权限数据，比如：如果用户身份数据在数据库那么realm就需要从数据库获取用户身份信息。<br />注意：<br />       不要把realm理解成只是从数据源取数据，在realm中还有认证授权校验的相关的代码
<a name="hWeKg"></a>
## SessionManager  会话管理
shiro框架定义了一套会话管理，它不依赖web容器的session，所以shiro可以使用在非web应用上，也可以将分布式应用的会话集中在一点管理，此特性可使它实现单点登录。
<a name="iF48X"></a>
## SessionDAO 会话DAO
是对session会话操作的一套接口，比如要将session存储到数据库，可以通过jdbc将会话存储到数据库。
<a name="gPGyi"></a>
## CacheManager  缓存管理
将用户权限数据存储在缓存，这样可以提高性能。
<a name="eWS8g"></a>
## Cryptography 密码管理
shiro提供了一套加密/解密的组件，方便开发。比如提供常用的散列、加/解密等功能。
<a name="Q4FFN"></a>
# Shiro认证
<a name="ibNgu"></a>
## 认证流程
![c525acf54f0ed950d6da0b848fba8f7f.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1649569256825-c7f5836f-3170-4e60-877e-7606951643cf.png#clientId=u3562c086-199d-4&crop=0&crop=0&crop=1&crop=1&from=drop&id=u5bdc89db&margin=%5Bobject%20Object%5D&name=c525acf54f0ed950d6da0b848fba8f7f.png&originHeight=612&originWidth=2244&originalType=binary&ratio=1&rotation=0&showTitle=false&size=79278&status=done&style=none&taskId=u32e85b05-5127-46e8-9fc3-acf88e9a20c&title=)

- Subject：主体

访问系统的用户，主体可以是用户、程序等，进行认证的都称为主体

- Principal：身份信息

是主体（subject）进行身份认证的标识，标识必须具有唯一性，如用户名、手机号、邮箱地址等，一个主体可以有多个身份，但是必须有一个主身份（Primary Principal）

- credential：凭证信息

是只有主体自己知道的安全信息，如密码、证书等
<a name="P628U"></a>
## 源码分析
<a name="DuPM3"></a>
### SecurityUtils
```java
public abstract class SecurityUtils {
    private static SecurityManager securityManager;
    // 获取Subject主体
    public static Subject getSubject() {
        Subject subject = ThreadContext.getSubject();
        if (subject == null) {
            subject = (new Subject.Builder()).buildSubject();
            ThreadContext.bind(subject);
        }
        return subject;
    }
    // 设置SecurityManager
    public static void setSecurityManager(SecurityManager securityManager) {
        SecurityUtils.securityManager = securityManager;
    }
    // 获取SecurityManager
    public static SecurityManager getSecurityManager() throws UnavailableSecurityManagerException {
        SecurityManager securityManager = ThreadContext.getSecurityManager();
        if (securityManager == null) {
            securityManager = SecurityUtils.securityManager;
        }
        if (securityManager == null) {
            String msg = "No SecurityManager accessible to the calling code, either bound to the " +
                    ThreadContext.class.getName() + " or as a vm static singleton.  This is an invalid application " +
                    "configuration.";
            throw new UnavailableSecurityManagerException(msg);
        }
        return securityManager;
    }
}
```
<a name="wZ8yC"></a>
### Realm 
![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1649571371393-4c23f272-34b9-4bc0-9d59-7fc6feab8b95.png#clientId=u3562c086-199d-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=711&id=z4Ei4&margin=%5Bobject%20Object%5D&name=image.png&originHeight=711&originWidth=1086&originalType=binary&ratio=1&rotation=0&showTitle=false&size=213090&status=done&style=none&taskId=ua6fd3ef6-079d-45af-af64-7ad9751b09f&title=&width=1086)
<a name="INhaX"></a>
### 认证授权
自定义认证授权 ------> 

- 继承AuthorizingRealm
- 重写doGetAuthenticationInfo和doGetAuthorizationInfo方法
```java
AuthenticatingRealm  认证
protected abstract AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException;

AuthorizingRealm     授权   继承AuthenticatingRealm
protected abstract AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals);
```
<a name="eHP7q"></a>
### SimpleAccountRealm
默认实现认证授权
```java
   // 认证
   protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        SimpleAccount account = getUser(upToken.getUsername());
        if (account != null) {
            if (account.isLocked()) {
                throw new LockedAccountException("Account [" + account + "] is locked.");
            }
            if (account.isCredentialsExpired()) {
                String msg = "The credentials for account [" + account + "] are expired";
                throw new ExpiredCredentialsException(msg);
            }
        }
        return account;
    }

    // 授权
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = getUsername(principals);
        USERS_LOCK.readLock().lock();
        try {
            return this.users.get(username);
        } finally {
            USERS_LOCK.readLock().unlock();
        }
    }
```
<a name="sw9pU"></a>
### AuthenticatingRealm
```java
public final AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
      AuthenticationInfo info = getCachedAuthenticationInfo(token);
      if (info == null) {
          
          // 验证username 返回用户信息
          info = doGetAuthenticationInfo(token);
          
          log.debug("Looked up AuthenticationInfo [{}] from doGetAuthenticationInfo", info);
          if (token != null && info != null) {
              cacheAuthenticationInfoIfPossible(token, info);
          }
      } else {
          log.debug("Using cached authentication info [{}] to perform credentials matching.", info);
      }
      if (info != null) {
          
          // 验证密码 默认为明文比较
          assertCredentialsMatch(token, info);
          
      } else {
          log.debug("No AuthenticationInfo found for submitted AuthenticationToken [{}].  Returning null.", token);
      }
      return info;
}
```
<a name="Uq40I"></a>
## 认证开发 （MAVEN）
<a name="GWGkp"></a>
### 创建项目
![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1649569483314-c0324f86-59b6-42a0-b9ad-8885b9608ee9.png#clientId=u3562c086-199d-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=675&id=u3d843211&margin=%5Bobject%20Object%5D&name=image.png&originHeight=675&originWidth=818&originalType=binary&ratio=1&rotation=0&showTitle=false&size=98325&status=done&style=none&taskId=uc96dc9cd-d5ad-4a54-8e7f-8b04443cafa&title=&width=818)
<a name="VURea"></a>
### 添加依赖
```xml
<dependencies>
     <!--shiro依赖-->
     <dependency>
        <groupId>org.apache.shiro</groupId>
        <artifactId>shiro-core</artifactId>
        <version>1.5.3</version>
     </dependency>
</dependencies>
```
<a name="JL8IV"></a>
### 引入Shiro配置文件
配置文件：名称随意，以 .ini 结尾，放在 resources 目录下
```xml
[users]
pepsi-wyl = 000000
zhazha = 000000
wyl = 000000
```
![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1649569698143-18a674b9-089f-450f-a129-12cd4468bda1.png#clientId=u3562c086-199d-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=450&id=uf9e68be6&margin=%5Bobject%20Object%5D&name=image.png&originHeight=450&originWidth=865&originalType=binary&ratio=1&rotation=0&showTitle=false&size=430411&status=done&style=none&taskId=u1a5b8c5f-1f97-4cef-be2e-92c4703b8f9&title=&width=865)
<a name="Pwun6"></a>
#### 下载插件
支持 *.ini 文件 <br />![20191102010521281.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1649569645172-b5b78851-8400-4357-91cd-e7158f2723d0.png#clientId=u3562c086-199d-4&crop=0&crop=0&crop=1&crop=1&from=drop&id=u406534dc&margin=%5Bobject%20Object%5D&name=20191102010521281.png&originHeight=816&originWidth=1032&originalType=binary&ratio=1&rotation=0&showTitle=false&size=191771&status=done&style=none&taskId=u52f172a2-06d1-4450-8b45-7dfceed5689&title=)
<a name="Jp2Gm"></a>
### 开发认证代码
```java
// 认证
public class Authenticator_T {
    public static void main(String[] args) {

        // 创建安全管理器
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        // 给安全管理器设置Realm
        securityManager.setRealm(new IniRealm("classpath:shiro.ini"));
        // SecurityUtils 全局安全工具类  给全局安全工具类设置安全管理器
        SecurityUtils.setSecurityManager(securityManager);
        // 主体对象
        Subject subject = SecurityUtils.getSubject();

        // 创建令牌
        UsernamePasswordToken token = new UsernamePasswordToken();
        token.setUsername("pepsi-wyl");
        token.setPassword("000000".toCharArray());

        try {
            // 用户认证 成功不抛出异常 失败抛出异常
            System.out.println("认证状态" + subject.isAuthenticated());
            subject.login(token); // 认证
            System.out.println("认证状态" + subject.isAuthenticated());
        } catch (UnknownAccountException e) {        // 未知账户错误
            System.out.println("认证失败:------>用户名不存在");
        } catch (IncorrectCredentialsException e) {  // 密码错误
            System.out.println("认证失败:------>密码错误");
        }
    }
}

//        DisabledAccountException（帐号被禁用）
//        LockedAccountException（帐号被锁定）
//        ExcessiveAttemptsException（登录失败次数过多）
//        ExpiredCredentialsException（凭证过期）等
```
<a name="qrgzI"></a>
## 加密
<a name="AfLno"></a>
### MD5
作用：一般用来加密或者签名（校验和）<br />特点：MD5算法不可逆如何内容相同无论执行多少次md5生成结果始终是一致<br />生成结果：始终是一个16进制32位长度字符串

实际应用：将 盐(salt)和散列(hash)后的值存在数据库中，自动realm从数据库取出盐和加密后的值由shiro完成密码校验。
```java
public class MD5_T {
    public static void main(String[] args) {
        // MD5 算法
        Md5Hash md5Hash = new Md5Hash("000000");
        System.out.println(md5Hash.toHex());
        // MD5 + Salt 算法
        Md5Hash md5HashSalt = new Md5Hash("000000", "X0*7ps");
        System.out.println(md5HashSalt);
        // MD5 + Salt + hash 散列 算法
        Md5Hash md5HashSaltHash = new Md5Hash("000000", "X0*7ps", 1024);
        System.out.println(md5HashSaltHash);
    }
}

// 670b14728ad9902aecba32e22fa4f6bd
// 1a3e6bec5916de834b285039af05e215
// f72b917515b1b479f20153edfa2dbb5f
```
<a name="Qpz63"></a>
## 自定义Realm
```java
public class CustomerRealm extends AuthorizingRealm {

    // 授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return null;
    }

    // 认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        // 数据库中的userName salt 加密后的密码
        String username = "pepsi-wyl";
        String salt = "X0*7ps";
        String password = "f72b917515b1b479f20153edfa2dbb5f";

        // 获取身份信息
        String principal = (String) token.getPrincipal();

        // 数据库查询 伪造数据
        if (username.equals(principal)) {
            //参数1:返回数据库中正确的用户名
            //参数2:返回数据库中正确密码
            //参数3:提供salt
            //参数4:提供当前realm的名字 this.getName();
            SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(
                    username, password, ByteSource.Util.bytes(salt),
                    this.getName());
            return simpleAuthenticationInfo;
        }

        return null;
    }
}
```
```java
// 认证
public class T {
    public static void main(String[] args) {

        /**
         * 加密操作
         */
        // 使用Hash凭证匹配器
        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName("md5");
        credentialsMatcher.setHashIterations(1024);

        // 设置Realm使用Hash凭证匹配器
        CustomerRealm customerRealm = new CustomerRealm();
        customerRealm.setCredentialsMatcher(credentialsMatcher);

        // 创建安全管理器 给安全管理器设置Realm
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealm(customerRealm);

        // SecurityUtils 全局安全工具类  给全局安全工具类设置安全管理器
        SecurityUtils.setSecurityManager(securityManager);
        // 主体对象
        Subject subject = SecurityUtils.getSubject();

        // 创建令牌
        UsernamePasswordToken token = new UsernamePasswordToken();
        token.setUsername("pepsi-wyl");
        token.setPassword("000000".toCharArray());

        try {
            // 用户认证 成功不抛出异常 失败抛出异常
            System.out.println("认证状态" + subject.isAuthenticated());
            subject.login(token); // 认证
            System.out.println("认证状态" + subject.isAuthenticated());
        } catch (UnknownAccountException e) {        // 未知账户错误
            System.out.println("认证失败:------>用户名不存在");
        } catch (IncorrectCredentialsException e) {  // 密码错误
            System.out.println("认证失败:------>密码错误");
        }

//        DisabledAccountException（帐号被禁用）
//        LockedAccountException（帐号被锁定）
//        ExcessiveAttemptsException（登录失败次数过多）
//        ExpiredCredentialsException（凭证过期）等

    }
}

```
<a name="JW5FB"></a>
# Shiro授权
<a name="h9sUf"></a>
## 授权流程
![2776d1da95d468069505ec23d87fe23e.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1649578803593-b89af5c3-19aa-40c9-b9c7-d9ad8b012ddc.png#clientId=u3562c086-199d-4&crop=0&crop=0&crop=1&crop=1&from=drop&id=u716054f6&margin=%5Bobject%20Object%5D&name=2776d1da95d468069505ec23d87fe23e.png&originHeight=1054&originWidth=3004&originalType=binary&ratio=1&rotation=0&showTitle=false&size=187660&status=done&style=none&taskId=u62d4b185-26a2-464e-8c10-f48466134e2&title=)<br />授权可简单理解为who对what(which)进行How操作：

- Who

即主体（Subject），主体需要访问系统中的资源。

- What

即资源（Resource)，如系统菜单、页面、按钮、类方法、系统商品信息等。资源包括资源类型和资源实例，比如商品信息为资源类型，类型为t01的商品为资源实例，编号为001的商品信息也属于资源实例。

- How

权限/许可（Permission)，规定了主体对资源的操作许可，权限离开资源没有意义，如用户查询权限、用户添加权限、某个类方法的调用权限、编号为001用户的修改权限等，通过权限可知主体对哪些资源都有哪些操作许可。
<a name="juChV"></a>
## 授权方式
<a name="tjqDo"></a>
### **基于角色的访问控制**
```java
RBAC基于角色的访问控制（Role-Based Access Control）
是以角色为中心进行访问控制
```
```java
if(subject.hasRole("admin")){
   //操作什么资源
}
```
<a name="cjgjy"></a>
### **基于资源的访问控制**
```java
RBAC基于资源的访问控制（Resource-Based Access Control）
是以资源为中心进行访问控制
```
```java
if(subject.isPermission("user:update:01")){ //资源实例
  //对资源01用户具有修改的权限
}
if(subject.isPermission("user:update:*")){  //资源类型
  //对 所有的资源 用户具有更新的权限
}
```
<a name="fVGES"></a>
#### 权限字符串
**规则：资源标识符：操作：资源实例标识符**
```markdown
对哪个资源的哪个实例具有什么操作
":"是资源/操作/实例的分割符
权限字符串也可以使用 * 通配符。
```
```java
用户创建权限：user:create，或user:create:*
用户修改实例001的权限：user:update:001
用户实例001的所有权限：user:*：001
```
<a name="cCacG"></a>
## 自定义Realm
```java
public class CustomerRealm extends AuthorizingRealm {
    // 授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {

        // 身份信息
        String primaryPrincipal = (String) principals.getPrimaryPrincipal();
        System.out.println("------>" + primaryPrincipal + "<------");

        // 根据身份信息 用户名 获取当前用户的角色信息，以及权限信息
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();

        /**
         * 角色
         */
        simpleAuthorizationInfo.addRole("user");
        simpleAuthorizationInfo.addRole("admin");

        /**
         * 权限字符串
         */
        simpleAuthorizationInfo.addStringPermission("user:*:01");
        simpleAuthorizationInfo.addStringPermission("product:*");   // 第三个参数为*可以省略

        return simpleAuthorizationInfo;
    }

    // 认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        // 数据库中的userName salt 加密后的密码
        String username = "pepsi-wyl";
        String salt = "X0*7ps";
        String password = "f72b917515b1b479f20153edfa2dbb5f";

        // 获取身份信息
        String principal = (String) token.getPrincipal();

        // 数据库查询 伪造数据
        if (username.equals(principal)) {
            //参数1:返回数据库中正确的用户名
            //参数2:返回数据库中正确密码
            //参数3:提供当前realm的名字 this.getName();
            SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(
                    username, password, ByteSource.Util.bytes(salt),
                    this.getName());
            return simpleAuthenticationInfo;
        }
        return null;
    }
}

```
```java
public class T {
    public static void main(String[] args) {

        // 设置Realm使用Hash凭证匹配器
        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName("md5");
        credentialsMatcher.setHashIterations(1024);

        // 给安全管理器设置Realm
//        securityManager.setRealm(new IniRealm("classpath:shiro.ini"));
        CustomerRealm customerRealm = new CustomerRealm();
        customerRealm.setCredentialsMatcher(credentialsMatcher);

        // 创建安全管理器
        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        securityManager.setRealm(customerRealm);

        // SecurityUtils 全局安全工具类  给全局安全工具类设置安全管理器
        SecurityUtils.setSecurityManager(securityManager);
        // 主体对象
        Subject subject = SecurityUtils.getSubject();

        // 创建令牌
        UsernamePasswordToken token = new UsernamePasswordToken();
        token.setUsername("pepsi-wyl");
        token.setPassword("000000".toCharArray());

        try {
            // 用户认证 成功不抛出异常 失败抛出异常
            System.out.println("认证状态" + subject.isAuthenticated());
            subject.login(token); // 认证
            System.out.println("认证状态" + subject.isAuthenticated());
        } catch (UnknownAccountException e) {        // 未知账户错误
            System.out.println("认证失败:------>用户名不存在");
        } catch (IncorrectCredentialsException e) {  // 密码错误
            System.out.println("认证失败:------>密码错误");
        }

//        DisabledAccountException（帐号被禁用）
//        LockedAccountException（帐号被锁定）
//        ExcessiveAttemptsException（登录失败次数过多）
//        ExpiredCredentialsException（凭证过期）等

        // 认证用户进行授权
        if (subject.isAuthenticated()) {

            /**
             * 基于角色
             */
            // 基于角色权限控制
            System.out.println("角色:" + subject.hasRole("admin"));

            // 基于多角色的权限控制
            System.out.println("角色:" + subject.hasAllRoles(Arrays.asList("user", "admin")));

            // 是否具有其中一个角色
            System.out.println("角色:" + Arrays.toString(subject.hasRoles(Arrays.asList("user", "super"))));

            /**
             * 基于权限字符串
             */
            // 基于单权限控制
            System.out.println("权限字符串：" + subject.isPermitted("user:*:*"));
            System.out.println("权限字符串：" + subject.isPermitted("user:*:01"));
            System.out.println("权限字符串：" + subject.isPermitted("user:update:01"));
            System.out.println("权限字符串：" + subject.isPermitted("product:update:01"));

            // 基于多权限控制
            System.out.println("权限字符串：" + subject.isPermittedAll("user:*:01", "product:update:01"));

            // 是否具有其中一个权限
            System.out.println("权限字符串：" + Arrays.toString(subject.isPermitted("user:*:*", "user:*:01")));
        }
    }
}

```
<a name="d3tNN"></a>
# 单体应用
<a name="Jg2Zj"></a>
## 技术

- Boot
- Thymleaf
- Shiro
- MP
- Mysql(Druid)
- Redis（Jedis）
- kaptcha
<a name="MVQya"></a>
## 环境配置
<a name="NlyXe"></a>
### 引入依赖
```xml
    <dependencies>

        <!--springBoot启动器-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter</artifactId>
        </dependency>

        <!--springBoot web启动器-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <!--thymeleaf模板视图-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>

        <!--
        shiro
        -->
        <!--引入shiro整合Springboot依赖-->
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-spring-boot-starter</artifactId>
            <version>1.9.0</version>
        </dependency>
        <!--引入Shiro和thymeleaf 拓展包-->
        <dependency>
            <groupId>com.github.theborakompanioni</groupId>
            <artifactId>thymeleaf-extras-shiro</artifactId>
            <version>2.1.0</version>
        </dependency>
        <!--引入Shiro和Ehcache EhCache实现缓存-->
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-ehcache</artifactId>
            <version>1.5.3</version>
        </dependency>

        <!--
        mysql->mybatis-plus
        -->
        <!--JDBC-mysql驱动-->
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <scope>runtime</scope>
        </dependency>
        <!--druid-dataSource 场景启动器-->
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>druid-spring-boot-starter</artifactId>
            <version>1.2.8</version>
        </dependency>
        <!--mybatis - plus场景启动器 内置了 jdbc启动场景-->
        <dependency>
            <groupId>com.baomidou</groupId>
            <artifactId>mybatis-plus-boot-starter</artifactId>
            <version>3.4.3.4</version>
        </dependency>

        <!--
        redis->jedis
        -->
        <!--redis-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        <!--jedis-->
        <dependency>
            <groupId>redis.clients</groupId>
            <artifactId>jedis</artifactId>
        </dependency>
        <!--redis池化技术-->
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-pool2</artifactId>
        </dependency>

        <!--验证码-->
        <dependency>
            <groupId>com.github.penggle</groupId>
            <artifactId>kaptcha</artifactId>
            <version>2.3.2</version>
        </dependency>
      
        <!--lombok插件简化Bean开发 @Slf4j日志打印-->
        <dependency>
            <groupId>org.projectlombok</groupId>
            <artifactId>lombok</artifactId>
        </dependency>
        <!--devtools支持热部署 静态页面实现热部署 ctrl+F9-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-devtools</artifactId>
            <scope>runtime</scope>
            <optional>true</optional>
        </dependency>
        <!--yaml配置提示 configuration-processor -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
        </dependency>

    </dependencies>
```
<a name="G0wUs"></a>
### yaml配置文件
```yaml
server:
  port: 80
  # servlet
  servlet:
    context-path: /

# spring
spring:
  application:
    name: shiroThemleaf
  # thymeleaf
  thymeleaf:
    cache: false
    suffix: .html
    prefix: classpath:/templates/
  # mysql
  datasource:
    username: root
    password: xxxxxx
    url: jdbc:mysql://localhost:3306/shiro?useSSL=true&useUnicode=true&characterEncoding=utf8&serverTimezone=UTC&rewriteBatchedStatements=true
    driver-class-name: com.mysql.cj.jdbc.Driver
    # druid
    type: com.alibaba.druid.spring.boot.autoconfigure.DruidDataSourceWrapper
    druid:
      initial-size: 5
      min-idle: 5
      max-active: 20
      max-wait: 60000
      time-between-eviction-runs-millis: 60000
      min-evictable-idle-time-millis: 300000
      validation-query: SELECT 1 FROM DUAL
      test-while-idle: true
      test-on-return: false
      test-on-borrow: false
      pool-prepared-statements: true
      max-pool-prepared-statement-per-connection-size: 20
      break-after-acquire-failure: true
      time-between-connect-error-millis: 300000
      async-init: true
      remove-abandoned: true
      remove-abandoned-timeout: 1800
      transaction-query-timeout: 6000
      connection-properties: druid.stat.mergeSql=true;druid.stat.slowSqlMillis=500
      use-global-data-source-stat: true
      aop-patterns: com.pepsiwyl.service.*

      filters: stat,wall
      filter:
        stat:
          enabled: true
          slow-sql-millis: 1000
          log-slow-sql: true
        wall:
          enabled: true
          config:
            drop-table-allow: false

      stat-view-servlet:
        enabled: true
        url-pattern: /druid/*
        reset-enable: false
        login-username: 'pepsi-wyl'
        login-password: '000000'
        allow:
        deny:

      web-stat-filter:
        enabled: true
        url-pattern: /*
        exclusions: /druid/*,*.js,*.gif,*.jpg,*.bmp,*.png,*.css,*.ico
        session-stat-enable: true
        session-stat-max-count: 10
        principal-session-name: session_name
        principal-cookie-name: cookie_name

  # redis
  redis:
    host: 101.43.169.194
    port: 6379
    password: xxxxxx
    database: 0
    # jedis
    client-type: jedis
    jedis:
      pool:
        max-active: 20
        max-idle: 5
        min-idle: 0

# mybatis-plus
mybatis-plus:
  configuration:
    log-impl: org.apache.ibatis.logging.stdout.StdOutImpl
  type-aliases-package: com.pepsiwyl.pojo
  mapper-locations: classpath*:/mapper/**/*.xml
```
<a name="TNbig"></a>
## Config
<a name="LkfN6"></a>
### WebMVCConfig
```java
@Configuration
public class WebMVCConfig implements WebMvcConfigurer {

    /**
     * ViewControllers
     *
     * @param registry
     */
    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("login");
        registry.addViewController("/toLogin").setViewName("login");
        registry.addViewController("/toRegister").setViewName("register");
        registry.addViewController("/toIndex").setViewName("index");
    }

}

```
<a name="co0kx"></a>
### MybatisPlusConfig
```java
@Configuration
@EnableTransactionManagement               //事务管理器
public class MybatisPlusConfig {

}
```
<a name="fyv61"></a>
### RedisConfig
```java
@EnableCaching  // 开启缓存
@Configuration  // redis配置类
public class RedisConfig {

}
```
<a name="OkfqP"></a>
### kaptchaConfig
```java
@Configuration
public class kaptchaConfig {
    
    @Bean(name = "captchaProducer")
    public DefaultKaptcha getKaptchaBean() {
        DefaultKaptcha defaultKaptcha = new DefaultKaptcha();
        Properties properties = new Properties();
        //验证码字符范围
        //        properties.setProperty("kaptcha.textproducer.char.string", "23456789");
        //图片边框颜色
        properties.setProperty("kaptcha.border.color", "245,248,249");
        //字体颜色
        properties.setProperty("kaptcha.textproducer.font.color", "black");
        //文字间隔
        properties.setProperty("kaptcha.textproducer.char.space", "1");
        //图片宽度
        properties.setProperty("kaptcha.image.width", "100");
        //图片高度
        properties.setProperty("kaptcha.image.height", "35");
        //字体大小
        properties.setProperty("kaptcha.textproducer.font.size", "30");
        //session的key
        //properties.setProperty("kaptcha.session.key", "code");
        //长度
        properties.setProperty("kaptcha.textproducer.char.length", "4");
        //字体
        properties.setProperty("kaptcha.textproducer.font.names", "宋体,楷体,微软雅黑");
        Config config = new Config(properties);
        defaultKaptcha.setConfig(config);
        return defaultKaptcha;
    }
}
```
<a name="FRWIX"></a>
### ShiroConfig
```java
@Configuration
public class ShiroConfig {

    /**
     * 加入方言处理 避免标签不识别
     *
     * @return
     */
    @Bean(name = "shiroDialect")
    public ShiroDialect shiroDialect() {
        return new ShiroDialect();
    }

    /**
     * cookie管理对象
     * rememberMeManager()方法是生成rememberMe管理器，而且要将这个rememberMe管理器设置到securityManager中
     *
     * @return
     */
    public CookieRememberMeManager rememberMeManager() {
        CookieRememberMeManager cookieRememberMeManager = new CookieRememberMeManager();

        // 设置cookie名称，对应login.html页面的<input type="checkbox" name="rememberMe"/>
        SimpleCookie cookie = new SimpleCookie("rememberMe");
        // 设置cookie的过期时间，单位为秒，这里为一天
        cookie.setMaxAge(86400);
        cookieRememberMeManager.setCookie(cookie);

        // rememberMe cookie加密的密钥 建议每个项目都不一样 默认AES算法 密钥长度(128 256 512 位)
        cookieRememberMeManager.setCipherKey(Base64.decode("3AvVhmFLUs0KTA3Kprsdag=="));
        return cookieRememberMeManager;
    }

    /**
     * 安全管理器
     */
    @Bean("defaultWebSecurityManager")
    public DefaultWebSecurityManager getSecurityManager(
            @Qualifier("userRealm") UserRealm userRealm,
            @Qualifier("redisCacheManger") RedisCacheManger redisCacheManger) {

        // Realm 使用 凭证匹配器 MD5
        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName(ConstUtils.MD5);
        credentialsMatcher.setHashIterations(ConstUtils.HashNumber);
        userRealm.setCredentialsMatcher(credentialsMatcher);

        // Realm 缓存管理器
        userRealm.setCachingEnabled(true);
        userRealm.setAuthenticationCachingEnabled(true); // 认证
        userRealm.setAuthenticationCacheName("authenticationCache");
        userRealm.setAuthorizationCachingEnabled(true);  // 授权
        userRealm.setAuthorizationCacheName("authorizationCache");
//        userRealm.setCacheManager(new EhCacheManager());
        userRealm.setCacheManager(redisCacheManger);


        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 给安全管理器设置Realm
        securityManager.setRealm(userRealm);
        // 给安全管理器设置RememberMeManager
        securityManager.setRememberMeManager(rememberMeManager());

        return securityManager;
    }

    /**
     * ShiroFilter 负责拦截请求
     */
    @Bean("shiroFilterFactoryBean")
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(
            @Qualifier("defaultWebSecurityManager") DefaultWebSecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();

        // 给Filter设置安全管理器
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        // 配置公共资源  配置受限资源  通配符进行认证
        HashMap<String, String> map = new HashMap<>();
        map.put("/druid/**", "anon");
        map.put("/", "anon");
        map.put("/toLogin", "anon");
        map.put("/toRegister", "anon");
        map.put("/user/login", "anon");
        map.put("/user/register", "anon");
        map.put("/user/getImage", "anon");  // 验证码不受限制
        map.put("/**", "authc");            // 所有资源都受限
        shiroFilterFactoryBean.setFilterChainDefinitionMap(map);

        // 默认认证界面路径---当认证不通过时跳转 设置登陆页面
        shiroFilterFactoryBean.setLoginUrl("/toLogin");

        return shiroFilterFactoryBean;
    }

}
```
<a name="GHnVx"></a>
## Mapper
<a name="tJsUT"></a>
### Database
<a name="vzsV5"></a>
#### SQL
```sql
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for t_user
-- ----------------------------
DROP TABLE IF EXISTS `t_user`;
CREATE TABLE `t_user`
(
    `id`       bigint NOT NULL AUTO_INCREMENT,
    `username` varchar(40)  DEFAULT NULL unique,
    `password` varchar(40)  DEFAULT NULL,
    `salt`     varchar(255) DEFAULT NULL,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  AUTO_INCREMENT = 2
  DEFAULT CHARSET = utf8;

-- ----------------------------
-- Table structure for t_role
-- ----------------------------
DROP TABLE IF EXISTS `t_role`;
CREATE TABLE `t_role`
(
    `id`   int(6) NOT NULL AUTO_INCREMENT,
    `name` varchar(60) DEFAULT NULL,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8;

-- ----------------------------
-- Table structure for t_perms
-- ----------------------------
DROP TABLE IF EXISTS `t_perms`;
CREATE TABLE `t_perms`
(
    `id`   int(6) NOT NULL AUTO_INCREMENT,
    `name` varchar(80)  DEFAULT NULL,
    `url`  varchar(255) DEFAULT NULL,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8;

-- ----------------------------
-- Table structure for t_role_perms
-- ----------------------------
DROP TABLE IF EXISTS `t_role_perms`;
CREATE TABLE `t_role_perms`
(
    `id`      int(6) NOT NULL,
    `roleid`  int(6) DEFAULT NULL,
    `permsid` int(6) DEFAULT NULL,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8;

-- ----------------------------
-- Table structure for t_user_role
-- ----------------------------
DROP TABLE IF EXISTS `t_user_role`;
CREATE TABLE `t_user_role`
(
    `id`     int(6) NOT NULL,
    `userid` bigint DEFAULT NULL,
    `roleid` int(6) DEFAULT NULL,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8;

SET FOREIGN_KEY_CHECKS = 1;
```
<a name="AGjy9"></a>
#### 表结构
![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650158265641-3d4b8fb1-f09d-4ed1-82ac-4cdb7704c03e.png#clientId=u2bd0b237-d1ea-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=193&id=ud7e78194&margin=%5Bobject%20Object%5D&name=image.png&originHeight=193&originWidth=393&originalType=binary&ratio=1&rotation=0&showTitle=false&size=73956&status=done&style=none&taskId=u97c4344d-fd43-4dbb-a338-325ec1a75f6&title=&width=393)<br />![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650158342159-704854b3-de09-42bc-aaa8-90c832fb283e.png#clientId=u2bd0b237-d1ea-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=32&id=u02534c38&margin=%5Bobject%20Object%5D&name=image.png&originHeight=32&originWidth=468&originalType=binary&ratio=1&rotation=0&showTitle=false&size=14044&status=done&style=none&taskId=u80655026-e512-4824-b675-612399f9f8b&title=&width=468)
<a name="q0pVv"></a>
#### 表内容
![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650158356767-3b23661a-dc81-4d4b-a5e4-367dce522f0a.png#clientId=u2bd0b237-d1ea-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=239&id=ud5799f9f&margin=%5Bobject%20Object%5D&name=image.png&originHeight=239&originWidth=830&originalType=binary&ratio=1&rotation=0&showTitle=false&size=250296&status=done&style=none&taskId=udbe5e3eb-e8b9-4229-a7cd-df2e08a6a6c&title=&width=830)<br />![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650158365535-42427e2e-aec9-4093-8c91-21c8ec2ef721.png#clientId=u2bd0b237-d1ea-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=256&id=u5b90d123&margin=%5Bobject%20Object%5D&name=image.png&originHeight=256&originWidth=641&originalType=binary&ratio=1&rotation=0&showTitle=false&size=194420&status=done&style=none&taskId=ud394a59e-9d7a-474e-a3d6-0dd1f75215e&title=&width=641)<br />![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650158397683-654184ef-15cd-4021-9993-75e6cbeb2e19.png#clientId=u2bd0b237-d1ea-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=389&id=u04c7df1d&margin=%5Bobject%20Object%5D&name=image.png&originHeight=389&originWidth=645&originalType=binary&ratio=1&rotation=0&showTitle=false&size=314004&status=done&style=none&taskId=ua4bfd052-22a6-4453-b8e9-1166198d3b1&title=&width=645)<br />![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650158378895-08fa4554-7156-47c0-a510-b7f2cd950a4e.png#clientId=u2bd0b237-d1ea-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=255&id=ub635d3b1&margin=%5Bobject%20Object%5D&name=image.png&originHeight=255&originWidth=642&originalType=binary&ratio=1&rotation=0&showTitle=false&size=201198&status=done&style=none&taskId=ub79530ca-e88f-4a3b-9fdd-cc8f59ae03b&title=&width=642)<br />![image.png](https://cdn.nlark.com/yuque/0/2022/png/23219042/1650158406588-b27a25c7-05d5-4d5a-98ed-19f7fd76e324.png#clientId=u2bd0b237-d1ea-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=309&id=u3493f2fd&margin=%5Bobject%20Object%5D&name=image.png&originHeight=309&originWidth=638&originalType=binary&ratio=1&rotation=0&showTitle=false&size=231232&status=done&style=none&taskId=u103ccf86-05f8-4744-8825-4c7ac02f043&title=&width=638)
<a name="eLb1t"></a>
### POJO
<a name="bY1l0"></a>
#### User
```java
// lombok注解
@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode

// 别名
@Alias("user")
// 数据库名称 表名称
@TableName(schema = "shiro", value = "t_user")

// 注册组件
@Component("user")
public class User {

    // 主键 雪花算法
    @TableId(value = "id", type = IdType.ASSIGN_ID)
    private Long id;

    private String username;

    // MD5 + salt + hash 加密
    private String password;

    /**
     * salt 盐字段 加密
     */
    private String salt;

}
```
<a name="v6MZj"></a>
#### Role
```java
// lombok注解
@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode

// 别名
@Alias("role")
// 数据库名称 表名称
@TableName(schema = "shiro", value = "t_role")

// 注册组件
@Component("role")
public class Role {

    @TableId(value = "id", type = IdType.AUTO)
    private String id;

    private String name;

}
```
<a name="FvkfU"></a>
#### Perms
```java
// lombok注解
@Data
@AllArgsConstructor
@NoArgsConstructor
@EqualsAndHashCode


// 别名
@Alias("perms")
// 数据库名称 表名称
@TableName(schema = "shiro", value = "t_perms")

// 注册组件
@Component("perms")
public class Perms {

    @TableId(value = "id", type = IdType.AUTO)
    private String id;

    private String name;
    private String url;

}
```
<a name="Yjywv"></a>
### Mapper
<a name="jiPFk"></a>
#### User
```java
@Transactional

@Mapper
public interface UserMapper extends BaseMapper<User> {

}
```
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Config 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">

<mapper namespace="com.pepsiwyl.mapper.UserMapper">

</mapper>
```
<a name="BxReW"></a>
#### Role
```java
@Transactional

@Mapper
public interface RoleMapper extends BaseMapper<Role> {

    /**
     * 根据用户名查询角色
     *
     * @param username
     * @return list Role
     */
    List<Role> getRolesByUserName(String username);

}
```
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Config 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">

<mapper namespace="com.pepsiwyl.mapper.RoleMapper">
  
  <!--根据用户名查询角色-->
  <select id="getRolesByUserName" parameterType="String" resultType="role" >
    select name
    from shiro.t_user u,
    shiro.t_role r,
    shiro.t_user_role ur
    where u.id = ur.userid
    and r.id = ur.roleid
    and u.username = #{username};
  </select>
  
</mapper>
```
<a name="Tdy1E"></a>
#### Perms
```java
@Transactional

@Mapper
public interface PermsMapper extends BaseMapper<Perms> {

    /**
     * 根据角色查询权限集合
     *
     * @param roleName
     * @return list Perms
     */
    List<Perms> getPermsByRoleName(String roleName);

}
```
```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Config 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">

<mapper namespace="com.pepsiwyl.mapper.PermsMapper">

    <!--根据角色id查询权限集合-->
    <select id="getPermsByRoleName" parameterType="String" resultType="perms">
        select p.id, p.name
        from t_role r,
             t_perms p,
             t_role_perms rp
        where r.id = rp.roleid
          and p.id = rp.permsid
          and r.name = #{roleName};
    </select>

</mapper>
```
<a name="XM895"></a>
## Utils
<a name="uoiC6"></a>
### ApplicationContextUtils
```java
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

@Component
public class ApplicationContextUtils implements ApplicationContextAware {

    private static ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext context) {
        applicationContext = context;
    }

    /**
     * 获取applicationContext
     *
     * @return Context
     */
    public static ApplicationContext getApplicationContext() {
        return applicationContext;
    }

    /**
     * 通过name获取Bean.
     *
     * @param name 名称
     * @return bean
     */
    public static Object getBean(String name) {
        return getApplicationContext().getBean(name);
    }

    /**
     * 通过class获取Bean.
     *
     * @param clazz
     * @return Bean
     */
    public static <T> T getBean(Class<T> clazz) {
        return getApplicationContext().getBean(clazz);
    }

    /**
     * 通过name,以及Clazz返回指定的Bean
     *
     * @param name  名称
     * @param clazz 类
     * @return Bean
     */
    public static <T> T getBean(String name, Class<T> clazz) {
        return getApplicationContext().getBean(name, clazz);
    }

}

```
<a name="KAJer"></a>
### SaltUtils
```java
import java.util.Random;

// 盐 随机
public class SaltUtils {

    // 字典
    private final static String str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /**
     * 生成 随机盐
     *
     * @param length 生成的长度
     * @return 随机盐
     */
    public static String getSalt(int length) {
        StringBuffer buffer = new StringBuffer();
        for (int i = 0; i < length; i++) buffer.append(str.charAt(new Random().nextInt(str.length())));
        return buffer.toString();
    }

}
```
<a name="f1Hrc"></a>
### ConstUtils
```java
public class ConstUtils {

    /**
     * hash 次数
     */
    public static final int HashNumber = 1024;

    /**
     * salt位数
     */
    public static final int SaltNumber = 8;

    /**
     * MD5
     */
    public static final String MD5 = "md5";

}
```
<a name="V2LYu"></a>
## Service
<a name="dtKNI"></a>
### UserService
```java
public interface UserService extends IService<User> {

    /**
     * 注册用户信息
     *
     * @param user
     */
    boolean register(User user);

    /**
     * 根据用户名查询用户 登陆
     *
     * @param userName
     * @return 用户
     */
    User getUserByUserName(String userName);

}
```
```java
@Transactional

@Service("userService")
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

    /**
     * 注入UserMapper
     */
    @Resource(name = "userMapper")
    UserMapper userMapper;

    /**
     * 注册用户
     *
     * @param user
     */
    @Override
    public boolean register(User user) {
        // 查询用户名是否存在
        if (userMapper.selectCount(new QueryWrapper<User>().eq("username", user.getUsername())) == 0) {
            // 密码加密 MD5 + salt + hash
            String salt = SaltUtils.getSalt(ConstUtils.SaltNumber);
            
            user.setPassword(
                new Md5Hash(
                    user.getPassword(), 
                    salt, 
                    ConstUtils.HashNumber
                ).toHex()
            );
            user.setSalt(salt);
            
            // 插入用户
            userMapper.insert(user);
            return true;
        }
        // 注册失败 用户名重复
        return false;
    }

    /**
     * 根据用户名查询用户  登陆
     *
     * @param userName
     * @return 用户
     */
    @Override
    public User getUserByUserName(String userName) {
        return userMapper.selectOne(new QueryWrapper<User>().eq("username", userName));
    }

}
```
<a name="URdXq"></a>
### RoleService
```java
public interface RoleService  extends IService<Role> {

    /**
     * 根据用户名查询角色
     *
     * @param username
     * @return list Role
     */
    List<Role> getRolesByUserName(String username);

}
```
```java
@Transactional

@Service("roleService")
public class RoleServiceImpl extends ServiceImpl<RoleMapper, Role> implements RoleService {

    /**
     * 注入RoleMapper
     */
    @Resource(name = "roleMapper")
    RoleMapper roleMapper;

    @Override
    public List<Role> getRolesByUserName(String username) {
        return roleMapper.getRolesByUserName(username);
    }

}
```
<a name="JTAtq"></a>
### PermsService
```java
public interface PermsService extends IService<Perms> {

    /**
     * 根据角色查询权限集合
     *
     * @param roleName
     * @return list Perms
     */
    List<Perms> getPermsByRoleName(String roleName);

}
```
```java
@Transactional

@Service("permsService")
public class PermsServiceImpl extends ServiceImpl<PermsMapper, Perms> implements PermsService {

    /**
     * 注入PermsMapper
     */
    @Resource(name = "permsMapper")
    PermsMapper permsMapper;

    @Override
    public List<Perms> getPermsByRoleName(String roleName) {
        return permsMapper.getPermsByRoleName(roleName);
    }

}
```
<a name="hDmdM"></a>
## Shiro
<a name="xPdAC"></a>
### Salt
```java
// salt 序列化与反序列化 解决redis序列化问题 bug
public class SaltByteSource implements ByteSource, Serializable {

    private byte[] bytes;
    private String cachedHex;
    private String cachedBase64;

    public SaltByteSource() {

    }

    public SaltByteSource(byte[] bytes) {
        this.bytes = bytes;
    }

    public SaltByteSource(char[] chars) {
        this.bytes = CodecSupport.toBytes(chars);
    }

    public SaltByteSource(String string) {
        this.bytes = CodecSupport.toBytes(string);
    }

    public SaltByteSource(ByteSource source) {
        this.bytes = source.getBytes();
    }

    public SaltByteSource(File file) {
        this.bytes = (new com.pepsiwyl.shiro.salt.SaltByteSource.BytesHelper()).getBytes(file);
    }

    public SaltByteSource(InputStream stream) {
        this.bytes = (new com.pepsiwyl.shiro.salt.SaltByteSource.BytesHelper()).getBytes(stream);
    }

    public static boolean isCompatible(Object o) {
        return o instanceof byte[] || o instanceof char[] || o instanceof String || o instanceof ByteSource || o instanceof File || o instanceof InputStream;
    }

    public byte[] getBytes() {
        return this.bytes;
    }

    public boolean isEmpty() {
        return this.bytes == null || this.bytes.length == 0;
    }

    public String toHex() {
        if (this.cachedHex == null) {
            this.cachedHex = Hex.encodeToString(this.getBytes());
        }

        return this.cachedHex;
    }

    public String toBase64() {
        if (this.cachedBase64 == null) {
            this.cachedBase64 = Base64.encodeToString(this.getBytes());
        }

        return this.cachedBase64;
    }

    public String toString() {
        return this.toBase64();
    }

    public int hashCode() {
        return this.bytes != null && this.bytes.length != 0 ? Arrays.hashCode(this.bytes) : 0;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        } else if (o instanceof ByteSource) {
            ByteSource bs = (ByteSource) o;
            return Arrays.equals(this.getBytes(), bs.getBytes());
        } else {
            return false;
        }
    }

    private static final class BytesHelper extends CodecSupport {
        private BytesHelper() {
        }

        public byte[] getBytes(File file) {
            return this.toBytes(file);
        }

        public byte[] getBytes(InputStream stream) {
            return this.toBytes(stream);
        }
    }

}
```
<a name="PVyhn"></a>
### realm
```java
@Slf4j

@Component("userRealm")
public class UserRealm extends AuthorizingRealm {

    /**
     * 注入UserService RoleService PermsService模板
     */
    @Resource(name = "userService")
    UserService userService;
    @Resource(name = "roleService")
    RoleService roleService;
    @Resource(name = "permsService")
    PermsService permsService;

    // 认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        // 得到用户名信息
        String principal = (String) authenticationToken.getPrincipal();
        log.info("认证 ------>" + principal + "<------");

        // 用户名认证
        User user = userService.getUserByUserName(principal);
        if (!ObjectUtils.isEmpty(user)) {
            // 密码认证 由SecurityManager 自动认证(需要配置MD5)
            return new SimpleAuthenticationInfo(
                    user.getUsername(),
                    user.getPassword(),
                    new SaltByteSource(user.getSalt()),
                    this.getName()
            );
        }
        // 用户名称错误
        return null;
    }

    // 授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        String primaryPrincipal = (String) principalCollection.getPrimaryPrincipal();
        log.info("授权 ------>" + primaryPrincipal + "<------");

        /**
         * 授权
         */
        // 数据库查询得到Roles
        List<Role> roles = roleService.getRolesByUserName(primaryPrincipal);
        if (!CollectionUtils.isEmpty(roles)) {
            roles.forEach(role -> {
                simpleAuthorizationInfo.addRole(role.getName());
                // 数据库查询得到Perms
                List<Perms> perms = permsService.getPermsByRoleName(role.getName());
                perms.forEach(perm -> {
                    simpleAuthorizationInfo.addStringPermission(perm.getName());
                });
            });
        }
        return simpleAuthorizationInfo;
    }

}
```
<a name="b0U4d"></a>
### Cache
```java
@Slf4j

@Component("redisCacheManger")
// redis 充当Shiro中缓存管理器
public class RedisCacheManger implements CacheManager {

    @Override
    public <K, V> Cache<K, V> getCache(String cacheName) throws CacheException {
        return new RedisCache<K, V>(cacheName);
    }

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    class RedisCache<K, V> implements Cache<K, V> {

        /**
         * cacheName
         */
        private String cacheName;

        /**
         * redisTemplate
         *
         * @return
         */
        private RedisTemplate getRedisTemplate() {
            RedisTemplate redisTemplate = ApplicationContextUtils.getBean("redisTemplate", RedisTemplate.class);
            redisTemplate.setKeySerializer(new StringRedisSerializer());
            redisTemplate.setHashKeySerializer(new StringRedisSerializer());
            return redisTemplate;
        }

        @Override
        public V get(K k) throws CacheException {
            log.info("get key:" + k);
            return (V) getRedisTemplate().opsForHash().get(this.cacheName, k.toString());
        }

        @Override
        public V put(K k, V v) throws CacheException {
            log.info("put key: " + k + " value:" + v);
            getRedisTemplate().opsForHash().put(this.cacheName, k.toString(), v);
            return null;
        }

        @Override
        public V remove(K k) throws CacheException {
            log.info("=============remove=============");
            return (V) getRedisTemplate().opsForHash().delete(this.cacheName, k.toString());
        }

        @Override
        public void clear() throws CacheException {
            log.info("=============clear=============");
            getRedisTemplate().delete(this.cacheName);
        }

        @Override
        public int size() {
            return getRedisTemplate().opsForHash().size(this.cacheName).intValue();
        }

        @Override
        public Set<K> keys() {
            return getRedisTemplate().opsForHash().keys(this.cacheName);
        }

        @Override
        public Collection<V> values() {
            return getRedisTemplate().opsForHash().values(this.cacheName);
        }

    }

}
```
<a name="leZ7J"></a>
## Controller
<a name="bbp2P"></a>
### UserController
```java
@Slf4j

@Controller
@RequestMapping(name = "用户控制器", path = "/user")
public class UserController {

    /**
     * 注入UserService
     */
    @Resource(name = "userService")
    UserService userService;

    /**
     * 注入captchaProducer
     */
    @Resource(name = "captchaProducer")
    private Producer captchaProducer;

    /**
     * loginController
     *
     * @param user
     * @return 失败--> 页面  成功---> 页面
     */
    @PostMapping(name = "用户登陆", path = "/login")
    public String login(User user,
                        @RequestParam("vcode") String vcode,
                        Boolean rememberMe,
                        HttpSession session) {
        log.info("登陆user------>" + user.toString());
        try {
            // 验证码比较
            if (vcode.equalsIgnoreCase((String) session.getAttribute(Constants.KAPTCHA_SESSION_KEY))) {
                // 认证登陆
                SecurityUtils.getSubject().login(new UsernamePasswordToken(user.getUsername(), user.getPassword(), rememberMe));
                log.info("认证成功:<------");
                // 跳转首页
                return "redirect:/toIndex";
            } else {
                throw new RuntimeException("验证码错误!!!");
            }
        } catch (UnknownAccountException e) {
            log.info("认证失败:------>用户名不存在!");
        } catch (IncorrectCredentialsException e) {
            log.info("认证失败:------>密码错误!");
        } catch (Exception e) {
            log.info("认证失败:------>验证码错误!");
        }
        // 跳转登陆页面
        return "redirect:/toLogin";
    }

    /**
     * registerController
     *
     * @param user
     * @return
     */
    @PostMapping(name = "用户注册", path = "/register")
    public String register(User user) {
        log.info("注册user------>" + user.toString());
        try {
            // 注册业务
            if (userService.register(user)) {
                log.info("注册成功:<------");
                // 跳转登陆页面
                return "redirect:/toLogin";
            } else {
                log.info("注册失败:------>用户名已经存在");
                return "redirect:/toRegister";
            }
        } catch (Exception e) {
            e.printStackTrace();
            // 发生异常 重新注册
            log.info("注册失败:------>发生异常");
            return "redirect:/toRegister";
        }
    }


    /**
     * logoutController
     *
     * @return 返回登陆页面
     */
    @GetMapping(name = "用户注销", path = "/logout")
    public String logout() {
        // 主体对象
        Subject subject = SecurityUtils.getSubject();
        // 注销登陆
        subject.logout();
        log.info("注销成功:<------");
        // 跳转登陆页面
        return "redirect:/toLogin";
    }

    /**
     * getImage 生成验证码
     *
     * @param session
     * @param response
     * @throws IOException
     */
    @RequestMapping(name = "生成验证码", path = "/getImage")
    public void getImage(HttpSession session, HttpServletResponse response) throws IOException {
        response.setDateHeader("Expires", 0);
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        response.addHeader("Cache-Control", "post-check=0, pre-check=0");
        response.setHeader("Pragma", "no-cache");
        response.setContentType("image/jpeg");
        //生成验证码
        String capText = captchaProducer.createText();
        log.info("capText------>" + capText);
        session.setAttribute(Constants.KAPTCHA_SESSION_KEY, capText);
        //向客户端写出
        BufferedImage bi = captchaProducer.createImage(capText);
        ServletOutputStream out = response.getOutputStream();
        ImageIO.write(bi, "jpg", out);
        try {
            out.flush();
        } finally {
            out.close();
        }
    }
}
```
<a name="ZCRJJ"></a>
## View
<a name="k8xTr"></a>
### Login
```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <script src="https://apps.bdimg.com/libs/jquery/2.1.4/jquery.min.js"></script>
    <script>
        $(function () {
            // 点击图片切换验证码
            $("#vcodeImg").click(function () {
                $(this).prop("src", "/user/getImage?t=" + new Date().getTime());    //为了避免浏览器的缓存机制，改变参数
            });
        });
    </script>
</head>
<body>
<h1>用户登陆</h1>
<a th:href="@{/toRegister}">注册</a>
<form th:action="@{/user/login}" method="post">
    用户名:<input type="text" name="username" required> <br/>
    密码 : <input type="password" name="password" required> <br>
    请输入验证码: <input type="text" name="vcode" required>
    <img id="vcodeImg" th:src="@{/user/getImage}" alt="" title="看不清？换一张"><br>
    <input type="checkbox" name="rememberMe"/>记住我
    <input type="submit" value="登录">
</form>
</body>
</html>
```
<a name="hKrjV"></a>
### Register
```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <title>Register</title>
</head>
<body>
<h1>用户注册</h1>

<a th:href="@{/toLogin}">登陆</a>

<form th:action="@{/user/register}" method="post">
    用户名:<input type="text" name="username" required> <br/>
    密码 : <input type="password" name="password" required> <br>
    <input type="submit" value="注册">
</form>
</body>
</html>
```
<a name="AUhuO"></a>
### Index
```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org"
      xmlns:shiro="http://www.pollix.at/thymeleaf/shiro">
<head>
    <meta charset="UTF-8">
    <title>index</title>
</head>
<body>

<h1>系统主页V1.0</h1>

<!-- 验证当前用户是否为“访客”，即未认证（包含未记住）的用户。 -->
<p shiro:guest="">Please <a th:href="@{/toLogin}">login</a></p>

<!-- 认证通过或已记住的用户。 -->
<p shiro:user="">
    Welcome back
    <shiro:principal/>
    ! Not
    <shiro:principal/>
    ? Click <a th:href="@{/toLogin}">here</a> to login.
</p>

<!-- 已认证通过的用户。不包含已记住的用户，这是与user标签的区别所在。 -->
<p shiro:authenticated="">
    欢迎[
    <shiro:principal/>
    ]登录 <a th:href="@{/user/logout}">退出登陆</a>
</p>

<ul>
    <shiro:hasAnyRoles name="user_manager,admin">
        <li><a href="">用户管理</a>
            <ul>
                <shiro:hasPermission name="user:add:*">
                    <li><a href="">添加</a></li>
                </shiro:hasPermission>
                <shiro:hasPermission name="user:delete:*">
                    <li><a href="">删除</a></li>
                </shiro:hasPermission>
                <shiro:hasPermission name="user:update:*">
                    <li><a href="">修改</a></li>
                </shiro:hasPermission>
                <shiro:hasPermission name="user:find:*">
                    <li><a href="">查询</a></li>
                </shiro:hasPermission>
            </ul>
        </li>
    </shiro:hasAnyRoles>

    <shiro:hasAnyRoles name="order_manager,admin">
        <li><a href="">订单管理</a></li>
        <ul>
            <shiro:hasPermission name="order:add:*">
                <li><a href="">添加</a></li>
            </shiro:hasPermission>
            <shiro:hasPermission name="order:delete:*">
                <li><a href="">删除</a></li>
            </shiro:hasPermission>
            <shiro:hasPermission name="order:update:*">
                <li><a href="">修改</a></li>
            </shiro:hasPermission>
            <shiro:hasPermission name="order:find:*">
                <li><a href="">查询</a></li>
            </shiro:hasPermission>
        </ul>
    </shiro:hasAnyRoles>
</ul>

</body>
</html>
```


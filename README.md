# EOS 智能合约现有安全漏洞(未完待续)

## 目录

* [已知漏洞](#已知漏洞)
   * [数值溢出](#数值溢出)
      * [漏洞示例](#漏洞示例)
      * [防御方法](#防御方法)
   * [权限校验](#权限校验)
      * [漏洞示例](#漏洞示例-1)
      * [防御方法](#防御方法-1)
   * [伪造EOS代币](#伪造EOS代币)
      * [漏洞示例](#漏洞示例-2)
      * [防御方法](#防御方法-2)
   * [伪造通知](#伪造通知)
      * [漏洞示例](#漏洞示例-3)
      * [防御方法](#防御方法-3)
   * [随机数预测](#随机数预测)
      * [漏洞示例](#漏洞示例-4)
      * [防御方法](#防御方法-4)
   * [回滚攻击](#回滚攻击)
      * [漏洞示例](#漏洞示例-5)
      * [防御方法](#防御方法-5)
   * [拥塞攻击](#拥塞攻击)
      * [漏洞示例](#漏洞示例-6)
      * [防御方法](#防御方法-6)
   * [耗尽资源](#耗尽资源)
      * [漏洞示例](#漏洞示例-7)
      * [防御方法](#防御方法-7)
   * [勒索攻击](#勒索攻击)
      * [漏洞示例](#漏洞示例-8)
      * [防御方法](#防御方法-8)


# 已知漏洞

## 数值溢出

在进行算术运算时，未进行边界检查可能导致数值上下溢，引起智能合约用户资产受损。
#### 漏洞示例
存在缺陷的代码：`batchtransfer` 批量转账

```c++
typedef struct acnts {
    account_name name0;
    account_name name1;
    account_name name2;
    account_name name3;
} account_names;

void batchtransfer(symbol_name symbol, account_name from, account_names to, uint64_t balance)
{
    require_auth(from);
    account fromaccount;

    require_recipient(from);
    require_recipient(to.name0);
    require_recipient(to.name1);
    require_recipient(to.name2);
    require_recipient(to.name3);

    eosio_assert(is_balance_within_range(balance), "invalid balance");
    eosio_assert(balance > 0, "must transfer positive balance");

    uint64_t amount = balance * 4; //乘法溢出

    int itr = db_find_i64(_self, symbol, N(table), from);
    eosio_assert(itr >= 0, "Sub-- wrong name");
    db_get_i64(itr, &fromaccount, (account));
    eosio_assert(fromaccount.balance >= amount, "overdrawn balance");

    sub_balance(symbol, from, amount);

    add_balance(symbol, to.name0, balance);
    add_balance(symbol, to.name1, balance);
    add_balance(symbol, to.name2, balance);
    add_balance(symbol, to.name3, balance);
}
```

#### 防御方法
尽可能使用 asset 结构体进行运算，而不是把 balance 提取出来进行运算。


### 权限校验

在进行相关操作时，应严格判断函数入参和实际调用者是否一致，使用`require_auth`进行校验。

#### 漏洞示例

存在缺陷的代码：`transfer` 转账

```c++
void token::transfer( account_name from,
                      account_name to,
                      asset        quantity,
                      string       memo )
{
    eosio_assert( from != to, "cannot transfer to self" );
    eosio_assert( is_account( to ), "to account does not exist");
    auto sym = quantity.symbol.name();
    stats statstable( _self, sym );
    const auto& st = statstable.get( sym );

    require_recipient( from );
    require_recipient( to );

    eosio_assert( quantity.is_valid(), "invalid quantity" );
    eosio_assert( quantity.amount > 0, "must transfer positive quantity" );
    eosio_assert( quantity.symbol == st.supply.symbol, "symbol precision mismatch" );
    eosio_assert( memo.size() <= 256, "memo has more than 256 bytes" );

    auto payer = has_auth( to ) ? to : from;

    sub_balance( from, quantity );
    add_balance( to, quantity, payer );
}
```

#### 防御方法

使用`require_auth( from )`校验资产转出账户与调用账户是否一致。



## 伪造EOS代币

在处理合约调用时，应确保每个 action 与 code 均满足关联要求。

#### 漏洞示例

存在缺陷的代码：

```c++
// extend from EOSIO_ABI
#define EOSIO_ABI_EX( TYPE, MEMBERS ) 
extern "C" { 
   void apply( uint64_t receiver, uint64_t code, uint64_t action ) {
      auto self = receiver; 
      if( action == N(onerror)) { 
         /* onerror is only valid if it is for the "eosio" code account and authorized by "eosio"'s "active permission */ 
         eosio_assert(code == N(eosio), "onerror action's are only valid from the \"eosio\" system account"); 
      } 
      if( code == self || code == N(eosio.token) || action == N(onerror) ) { 
         TYPE thiscontract( self ); 
         switch( action ) { 
            EOSIO_API( TYPE, MEMBERS ) 
         } 
         /* does not allow destructor of thiscontract to run: eosio_exit(0); */ 
      } 
   } 
}

EOSIO_ABI_EX(eosio::charity, (hi)(transfer))
```

#### 防御方法

使用

```
if( ((code == self  && action != N(transfer) ) || (code == N(eosio.token) && action == N(transfer)) || action == N(onerror)) ) { }
```

绑定每个关键 action 与 code 是否满足要求，避免异常调用。


## 伪造通知

在处理 `require_recipient` 触发的通知时，应确保 `transfer.to` 为 `_self`。

#### 漏洞示例

存在缺陷的代码：

```c++
// source code: https://gitlab.com/EOSBetCasino/eosbetdice_public/blob/master/EOSBetDice.cpp#L115
void transfer(uint64_t sender, uint64_t receiver) {

	auto transfer_data = unpack_action_data<st_transfer>();

	if (transfer_data.from == _self || transfer_data.from == N(eosbetcasino)){
		return;
	}

	eosio_assert( transfer_data.quantity.is_valid(), "Invalid asset");
}
```

#### 防御方法

增加

```
if (transfer_data.to != _self) return;
```


## 随机数预测

随机数生成算法不要引入可控或者可预测的种子

#### 漏洞示例

存在缺陷的代码：

```c++
// source code: https://github.com/loveblockchain/eosdice/blob/3c6f9bac570cac236302e94b62432b73f6e74c3b/eosbocai2222.hpp#L174
uint8_t random(account_name name, uint64_t game_id)
{
    auto eos_token = eosio::token(N(eosio.token));
    asset pool_eos = eos_token.get_balance(_self, symbol_type(S(4, EOS)).name());
    asset ram_eos = eos_token.get_balance(N(eosio.ram), symbol_type(S(4, EOS)).name());
    asset betdiceadmin_eos = eos_token.get_balance(N(betdiceadmin), symbol_type(S(4, EOS)).name());
    asset newdexpocket_eos = eos_token.get_balance(N(newdexpocket), symbol_type(S(4, EOS)).name());
    asset chintailease_eos = eos_token.get_balance(N(chintailease), symbol_type(S(4, EOS)).name());
    asset eosbiggame44_eos = eos_token.get_balance(N(eosbiggame44), symbol_type(S(4, EOS)).name());
    asset total_eos = asset(0, EOS_SYMBOL);
    //攻击者可通过inline_action改变余额total_eos，从而控制结果
    total_eos = pool_eos + ram_eos + betdiceadmin_eos + newdexpocket_eos + chintailease_eos + eosbiggame44_eos;
    auto mixd = tapos_block_prefix() * tapos_block_num() + name + game_id - current_time() + total_eos.amount;
    const char *mixedChar = reinterpret_cast<const char *>(&mixd);

    checksum256 result;
    sha256((char *)mixedChar, sizeof(mixedChar), &result);

    uint64_t random_num = *(uint64_t *)(&result.hash[0]) + *(uint64_t *)(&result.hash[8]) + *(uint64_t *)(&result.hash[16]) + *(uint64_t *)(&result.hash[24]);
    return (uint8_t)(random_num % 100 + 1);
}
```

#### 防御方法

EOS链上不能生成真随机数，在设计随机类应用时建议参考官方的示例

- [Randomization in Contracts](https://developers.eos.io/eosio-cpp/v1.3.2/docs/random-number-generation)


## 回滚攻击

- 手法1：在事务中探测执行结果(如收款金额、账号余额、表记录、随机数计算结果等)，当结果满足一定条件时调用 eosio_assert ，使得当前事务失败回滚。
- 手法2：利用超级节点黑名单账号发起事务，欺骗普通节点做出响应，但此事务不会被打包。

#### 漏洞示例

常见的有缺陷的模式：

- 博弈类游戏下注随即开奖并转账，恶意合约可通过 inline_action 检测余额是否增加，从而回滚失败的开奖
- 博弈类游戏下注随即将开奖结果写入表内，恶意合约可通过 inline_action 检测表中记录，从而回滚失败的开奖
- 博弈类游戏开奖结果与游戏内奖券号相关联，恶意合约可通过同时发起多笔小额下注事务和一笔大额下注事务，当收到小额中奖时回滚事务，从而达到将可中奖的奖券号“转让”给大额下注的目的。
- 博弈类游戏开奖事务与下注事务没有关联，攻击者可用黑名单账号或者恶意合约回滚下注事务

#### 防御方法

- 使用 defer action 转账和发送收据
- 建立开奖依赖，如订单依赖，开奖的时候判断订单是否存在，就算在节点服务器上开奖成功，由于在 bp 上下注订单被回滚，所以相应的开奖记录也会被回滚。


## 拥塞攻击

- 手法：攻击者在一个事务中启动大量延迟的垃圾事务，这些事务中可能包含死循环，从而造成超时，耗尽所有的CPU执行时间而瘫痪整个EOS网络。

#### 漏洞示例
暂无

#### 防御方法
- 限制每个块中处理当前挂起延迟事务的CPU时间，为当前用户签名事务预留尽可能多的时间。

## 耗尽资源

- 手法1：耗尽EOS-CPU资源：获得用户授权的eosio.code需要一些时间，合约提供者(SCP)通常需要抵押用户的EOS-CPU进行延迟事务处理。当受害者的EOS-CPU被耗尽的时候，相应的智能合约24小时内不可用。攻击者可以用自己少量的EOS-CPU耗尽受害者的EOS-CPU。
- 手法2：耗尽EOS内存资源：由于没有阻止用户向内存中存入无限数据，导致内存资源被消耗完。

#### 漏洞示例

暂无

#### 防御方法
合约提供者可以设计这么一种合约，用自己认可的代码创建一个合约，将执行合约的费用强加给自己，这样就可以避免对外授权，同样也消除了攻击者的目标。
当前的EOSIO系统支持限制运行智能合约最大资源使用，可以有效预防内存滥用

## 勒索攻击

- 手法：攻击者先上传一个良性的合约，这个合约先得到了eosio.code授权和检测结果，攻击者把好的检测结果上传到自己的网站上面，受害者当时看了检测结果和源码会认可这个良心合约，并把合约运行在自己的EOS.IO上，之后攻击者把良性合约偷换成恶意合约，受害者继续使用就会出事情。这个漏洞主要问题在于，EOS.IO系统在合约发生更新或覆盖的时候，并不提示用户合约已经改变了。

#### 漏洞示例

暂无

#### 防御方法
细分权限：目前EOS.IO权限系统的弊端就是，权限要么全给，要么都不给。因此，可以细分权限。让用户设定权限的特定范围或者特定版本。当一个合约被替换掉之后，所给的权限就会自动失效。或者设定授权到期时间，因为用户容易忘记撤销授权。

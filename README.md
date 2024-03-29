# 弹幕服务器

请使用 python3

运行
```bash
python3 main.py
```

## 限制算法

限制算法有两个首要目标

1. 限制每个用户（发送者）发送弹幕的频率 $sf (messages/s)$
2. 限制每个用户（接受者）收到弹幕的频率 $rf (m/s)$

设连接人数 $n$，实际发送系数 $ratio$，服务器吞吐量 $q$，则峰值为

$$
rf \geq n \times ratio \times sf 
\\
q = n^2 * ratio * sf
$$

由于 $rf$ 与 $sf$ 都是限制条件，那么决定哪个称为最终约束的，取决于 $m$, 当 $m$ 小的时候，$sf$ 是约束条件。


目前我们认为
$$
sf = \frac{1}{3}
\\
rf = 100
\\
ratio = 0.2
\\
n \leq 2000
$$



## 过滤

### 过滤规则

1. 空字符串
2. 超过长度限制
3. 已被禁止的用户

### 限制程度

- 禁止发送弹幕
- 禁止接收弹幕（不能连接）

## 通信接口

json 格式


```json
{
    "type": "danmaku|msg",
    
    "data":{ // danmaku
        "text": "",
        "color": "",
        "type": ""
    },


    "msg": "发送失败" // msg
    
}
```

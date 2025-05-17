# 前后端API接口规范

## 1. 概述

本文档定义了前后端交互的API接口规范，旨在统一前后端开发人员对接口的理解和使用方式，提高开发效率和代码质量。

## 2. 基本原则

- 遵循RESTful API设计原则
- 使用HTTPS协议进行通信
- 统一使用JSON格式进行数据交换
- 接口版本控制
- 规范的错误处理机制
- 完善的接口文档

## 3. 接口URL规范

### 3.1 基础URL结构

```
https://{domain}/{api-version}/{resource}/{resource-id}/{sub-resource}
```

- **domain**: 服务器域名
- **api-version**: API版本号，如v1, v2
- **resource**: 资源名称，使用复数形式，如users, products
- **resource-id**: 资源ID
- **sub-resource**: 子资源名称，如comments

### 3.2 URL示例

```
https://api.example.com/v1/users
https://api.example.com/v1/users/123
https://api.example.com/v1/users/123/posts
https://api.example.com/v1/users/123/posts/456
```

## 4. HTTP方法使用规范

| HTTP方法 | 用途 | 示例 |
|---------|------|------|
| GET | 获取资源 | GET /users |
| POST | 创建资源 | POST /users |
| PUT | 更新资源(全量更新) | PUT /users/123 |
| PATCH | 更新资源(部分更新) | PATCH /users/123 |
| DELETE | 删除资源 | DELETE /users/123 |

## 5. 请求参数规范

### 5.1 路径参数(Path Parameters)

路径参数直接包含在URL中，用于标识特定资源。

```
GET /users/{user_id}
```

### 5.2 查询参数(Query Parameters)

查询参数用于过滤、排序、分页等操作。

```
GET /users?page=1&limit=10&sort=name&order=asc
```

常用查询参数：

- **page**: 页码，默认为1
- **limit/size**: 每页记录数，默认为10
- **sort**: 排序字段
- **order**: 排序方式，asc(升序)或desc(降序)
- **q**: 搜索关键词
- **fields**: 指定返回的字段

### 5.3 请求体参数(Request Body)

请求体参数用于POST, PUT, PATCH请求，采用JSON格式。

```json
{
  "name": "张三",
  "email": "zhangsan@example.com",
  "age": 30,
  "roles": ["admin", "user"]
}
```

### 5.4 请求头参数(Headers)

常用的请求头：

- **Authorization**: 认证信息，如Bearer Token
- **Content-Type**: 内容类型，通常为application/json
- **Accept**: 客户端期望的响应格式
- **Accept-Language**: 客户端期望的语言
- **User-Agent**: 客户端信息

## 6. 响应规范

### 6.1 响应状态码

| 状态码 | 含义 | 说明 |
|-------|------|------|
| 200 | OK | 请求成功 |
| 201 | Created | 资源创建成功 |
| 204 | No Content | 请求成功，无返回内容 |
| 400 | Bad Request | 请求参数错误 |
| 401 | Unauthorized | 未认证 |
| 403 | Forbidden | 无权限 |
| 404 | Not Found | 资源不存在 |
| 409 | Conflict | 资源冲突 |
| 422 | Unprocessable Entity | 请求格式正确但语义错误 |
| 500 | Internal Server Error | 服务器内部错误 |

### 6.2 响应体格式

成功响应：

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "id": 123,
    "name": "张三",
    "email": "zhangsan@example.com"
  }
}
```

列表响应：

```json
{
  "code": 200,
  "message": "success",
  "data": {
    "total": 100,
    "page": 1,
    "limit": 10,
    "items": [
      {
        "id": 123,
        "name": "张三"
      },
      {
        "id": 124,
        "name": "李四"
      }
    ]
  }
}
```

错误响应：

```json
{
  "code": 400,
  "message": "参数错误",
  "errors": [
    {
      "field": "email",
      "message": "邮箱格式不正确"
    }
  ]
}
```

## 7. 认证与授权

### 7.1 认证方式

采用JWT(JSON Web Token)进行认证：

1. 客户端通过登录接口获取token
2. 后续请求在Authorization头中携带token

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### 7.2 授权策略

基于角色的访问控制(RBAC)：

- 用户关联角色
- 角色关联权限
- 接口定义所需权限

## 8. 接口文档规范

每个接口文档应包含以下内容：

- 接口名称和描述
- 请求URL
- 请求方法
- 请求参数说明
- 响应参数说明
- 请求示例
- 响应示例
- 错误码说明

## 9. 接口调用示例

### 9.1 用户登录

**请求：**

```http
POST /v1/auth/login HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "username": "zhangsan",
  "password": "password123"
}
```

**响应：**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "code": 200,
  "message": "success",
  "data": {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 3600,
    "user_info": {
      "id": 123,
      "name": "张三",
      "email": "zhangsan@example.com"
    }
  }
}
```

### 9.2 获取用户列表

**请求：**

```http
GET /v1/users?page=1&limit=10 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
```

**响应：**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "code": 200,
  "message": "success",
  "data": {
    "total": 100,
    "page": 1,
    "limit": 10,
    "items": [
      {
        "id": 123,
        "name": "张三",
        "email": "zhangsan@example.com",
        "created_at": "2023-01-01T12:00:00Z"
      },
      {
        "id": 124,
        "name": "李四",
        "email": "lisi@example.com",
        "created_at": "2023-01-02T12:00:00Z"
      }
    ]
  }
}
```

### 9.3 创建用户

**请求：**

```http
POST /v1/users HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json

{
  "name": "王五",
  "email": "wangwu@example.com",
  "password": "password123",
  "roles": ["user"]
}
```

**响应：**

```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "code": 201,
  "message": "用户创建成功",
  "data": {
    "id": 125,
    "name": "王五",
    "email": "wangwu@example.com",
    "created_at": "2023-01-03T12:00:00Z"
  }
}
```

## 10. 前端实现示例

### 10.1 使用Axios发起请求

```javascript
// 配置axios实例
const api = axios.create({
  baseURL: 'https://api.example.com/v1',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  }
});

// 请求拦截器，添加token
api.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// 响应拦截器，处理错误
api.interceptors.response.use(
  response => {
    return response.data;
  },
  error => {
    if (error.response) {
      // 处理401未授权错误，跳转到登录页
      if (error.response.status === 401) {
        localStorage.removeItem('token');
        router.push('/login');
      }
      return Promise.reject(error.response.data);
    }
    return Promise.reject(error);
  }
);

// 登录
async function login(username, password) {
  try {
    const response = await api.post('/auth/login', { username, password });
    localStorage.setItem('token', response.data.token);
    return response.data.user_info;
  } catch (error) {
    console.error('登录失败:', error);
    throw error;
  }
}

// 获取用户列表
async function getUsers(page = 1, limit = 10) {
  try {
    const response = await api.get('/users', {
      params: { page, limit }
    });
    return response.data;
  } catch (error) {
    console.error('获取用户列表失败:', error);
    throw error;
  }
}

// 创建用户
async function createUser(userData) {
  try {
    const response = await api.post('/users', userData);
    return response.data;
  } catch (error) {
    console.error('创建用户失败:', error);
    throw error;
  }
}
```

## 11. 后端实现示例

### 11.1 使用FastAPI实现接口

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
import jwt
from datetime import datetime, timedelta

app = FastAPI()

# 用户模型
class User(BaseModel):
    id: Optional[int] = None
    name: str
    email: str
    password: str
    roles: List[str] = []
    created_at: Optional[datetime] = None

# 用户响应模型
class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    created_at: datetime

# 登录请求模型
class LoginRequest(BaseModel):
    username: str
    password: str

# 登录响应模型
class LoginResponse(BaseModel):
    token: str
    expires_in: int
    user_info: UserResponse

# 分页响应模型
class PaginatedResponse(BaseModel):
    total: int
    page: int
    limit: int
    items: List[UserResponse]

# 通用响应模型
class ApiResponse(BaseModel):
    code: int
    message: str
    data: Optional[dict] = None
    errors: Optional[List[dict]] = None

# JWT配置
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# 模拟数据库
users_db = {
    "zhangsan": {
        "id": 123,
        "name": "张三",
        "email": "zhangsan@example.com",
        "password": "password123",
        "roles": ["admin", "user"],
        "created_at": datetime(2023, 1, 1, 12, 0, 0)
    }
}

# 认证依赖
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None or username not in users_db:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="无效的认证凭证",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return users_db[username]
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证凭证",
            headers={"WWW-Authenticate": "Bearer"},
        )

# 创建JWT token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 登录接口
@app.post("/auth/login", response_model=ApiResponse)
async def login(form_data: LoginRequest):
    user = users_db.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    
    user_response = UserResponse(
        id=user["id"],
        name=user["name"],
        email=user["email"],
        created_at=user["created_at"]
    )
    
    return {
        "code": 200,
        "message": "success",
        "data": {
            "token": access_token,
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user_info": user_response.dict()
        }
    }

# 获取用户列表接口
@app.get("/users", response_model=ApiResponse)
async def get_users(
    page: int = 1, 
    limit: int = 10,
    current_user: dict = Depends(get_current_user)
):
    # 检查权限
    if "admin" not in current_user["roles"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="没有足够的权限"
        )
    
    # 模拟分页
    users = list(users_db.values())
    total = len(users)
    start = (page - 1) * limit
    end = start + limit
    paginated_users = users[start:end]
    
    # 转换为响应模型
    user_responses = [
        UserResponse(
            id=user["id"],
            name=user["name"],
            email=user["email"],
            created_at=user["created_at"]
        ) for user in paginated_users
    ]
    
    return {
        "code": 200,
        "message": "success",
        "data": {
            "total": total,
            "page": page,
            "limit": limit,
            "items": [user.dict() for user in user_responses]
        }
    }

# 创建用户接口
@app.post("/users", response_model=ApiResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user: User,
    current_user: dict = Depends(get_current_user)
):
    # 检查权限
    if "admin" not in current_user["roles"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="没有足够的权限"
        )
    
    # 检查邮箱是否已存在
    for existing_user in users_db.values():
        if existing_user["email"] == user.email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="邮箱已存在"
            )
    
    # 创建新用户
    new_user = {
        "id": max([u["id"] for u in users_db.values()]) + 1 if users_db else 1,
        "name": user.name,
        "email": user.email,
        "password": user.password,
        "roles": user.roles,
        "created_at": datetime.utcnow()
    }
    
    # 保存到模拟数据库
    users_db[user.name] = new_user
    
    # 返回响应
    user_response = UserResponse(
        id=new_user["id"],
        name=new_user["name"],
        email=new_user["email"],
        created_at=new_user["created_at"]
    )
    
    return {
        "code": 201,
        "message": "用户创建成功",
        "data": user_response.dict()
    }

# 获取单个用户接口
@app.get("/users/{user_id}", response_model=ApiResponse)
async def get_user(
    user_id: int,
    current_user: dict = Depends(get_current_user)
):
    # 查找用户
    user = None
    for u in users_db.values():
        if u["id"] == user_id:
            user = u
            break
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )
    
    # 检查权限
    if current_user["id"] != user_id and "admin" not in current_user["roles"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="没有足够的权限"
        )
    
    # 返回响应
    user_response = UserResponse(
        id=user["id"],
        name=user["name"],
        email=user["email"],
        created_at=user["created_at"]
    )
    
    return {
        "code": 200,
        "message": "success",
        "data": user_response.dict()
    }
```

## 12. 版本控制与兼容性

### 12.1 版本控制策略

- 在URL中使用版本号，如/v1/users
- 主版本号变更表示不兼容的API更改
- 次版本号变更表示向后兼容的功能性新增
- 修订版本号变更表示向后兼容的问题修正

### 12.2 API废弃策略

- 新版本发布后，旧版本至少维护6个月
- 废弃的API在响应头中添加Deprecation警告
- 提前3个月通知用户API将被废弃

## 13. 安全性考虑

- 所有API通信必须使用HTTPS
- 敏感数据传输必须加密
- 实施速率限制防止滥用
- 实施CORS策略
- 防止常见的Web安全漏洞，如XSS、CSRF、SQL注入等
- 定期进行安全审计和渗透测试

## 14. 性能优化

- 使用适当的缓存策略
- 实施数据分页
- 支持部分响应（只返回客户端需要的字段）
- 压缩响应数据
- 使用CDN分发静态资源

## 15. 监控与日志

- 记录API调用日志
- 监控API性能指标
- 设置告警机制
- 定期分析API使用情况

## 16. 变更管理

- 记录API变更历史
- 提供API变更通知机制
- 制定API变更审批流程

## 17. 总结

本规范文档定义了前后端API接口的设计和实现标准，旨在提高开发效率、代码质量和系统可维护性。前端和后端工程师应严格遵循本规范，确保API接口的一致性和可靠性。
extern crate redis;
use warp::{Filter, path::FullPath};
use anyhow::Error;
use job_scheduler::{Job, JobScheduler};
use md5::{Digest, Md5};
use redis::{Client, Commands, RedisError};
use serde::{Deserialize, Serialize};
use serde_json;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use log::{info, error};
use log4rs;


// pwn1OS payload 提交方式：
// curl http://152.136.46.174:1024/n1ctf/submit?team=<team_name>&urlscheme=<base64(paylaod)>
// 示例：
// curl http://152.136.46.174:1024/n1ctf/submit?team=wangwangdui&urlscheme=bjFjdGY6Ly8=

// 查询提交的 payload 是否执行完成：
// curl http://152.136.46.174:1024/n1ctf/query?taskid=<taskid>
// 示例：
// curl http://152.136.46.174:1024/n1ctf/query?taskid=820f7b79e1206ce0de4c7c2cb4d27d10

// 禁止对该接口进行爆破、渗透等攻击行为

// n1ctf://web?url=http%3A%2F%2F172.16.113.96%3A9001%2Fpwn.html
// ObjC.classes.UIApplication.sharedApplication().openURL_(ObjC.classes.NSURL.URLWithString_("n1ctf://web?url=http%3A%2F%2F172.16.113.89%3A9001%2Fpwn.html"))

// http://127.0.0.1:1024/n1ctf/submit?urlscheme=bjFjdGY6Ly93ZWI/dXJsPWh0dHBzJTNBJTJGJTJGd3d3LmJhaWR1LmNvbQ==&team=wangwangdui
// http://127.0.0.1:1024/n1ctf/submit?urlscheme=bjFjdGY6Ly93ZWI/dXJsPWh0dHAlM0ElMkYlMkYxNzIuMTYuMTEzLjc5JTNBOTAwMSUyRnB3bi5odG1s&team=wangwangdui


const N1CTF_TASK_QUEUE: &str = "m_N1CTF_TASK_QUEUE";
const N1CTF_TASK_QUEUE_DONE: &str = "m_N1CTF_TASK_QUEUE_DONE";


pub struct RedisConnection {
    client: Client,
}


impl RedisConnection {
    pub fn connect(url: String) -> Result<Self, RedisError> {
        let client = Client::open(url)?;
        Ok(Self { client })
    }

    pub fn push_task(&self, payload: &String) -> Result<(), RedisError> {
        let mut connection = self.client.get_connection()?;
        connection.lpush(N1CTF_TASK_QUEUE, payload)
    }

    pub fn query_task(&self, task_id: &String) -> Result<N1CTFTask, Error> {
        let mut connection = self.client.get_connection().map_err(Error::from)?;

        let len: isize = connection.llen(N1CTF_TASK_QUEUE_DONE)?;
        let mut index = 0;
        while index as u32 != len as u32 {
            let json_str: String = connection.lindex(N1CTF_TASK_QUEUE_DONE, index)?;
            let json: N1CTFTask = serde_json::from_str(&json_str)?;
            if task_id.eq(&json.task_id) {
                return Ok(json);
            }
            index += 1;
        }
        return Err(Error::msg(format!(
            "N1CTF ERROR: con't find task: {}!",
            task_id
        )));
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct N1CTFTask {
    task_id: String,
    payload: String,
    timestamp: String,
    status: String,
}

fn get_timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}
fn get_task_key(team: &String) -> String {
    let time = get_timestamp();
    let mut hasher = Md5::new();
    let s_time = format!("{}{}{}{}", "y1HW30dTeu", time, team, "vstKDOukCN");
    hasher.update(s_time);
    hex::encode(hasher.finalize())
}


#[derive(Debug, Deserialize)]
struct SubmitParams {
    team: String,
    urlscheme: String,
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    taskid: String,
}



fn run() {
    // 定时脚本
    println!("定时脚本启动");
    let mut sched = JobScheduler::new();
    sched.add(Job::new("1/5 * * * * *".parse().unwrap(), move || {
        exec_cmd();
    }));
    loop {
        sched.tick();
        std::thread::sleep(Duration::from_millis(500));
    }
}


fn exec_cmd() {
    println!("[*] N1CTF 执行脚本");

    let cmd = "python3";
    let file = "../inject.py";
    // let file = "/Users/momo/Desktop/N1CTF\\ pwn1OS/inject.py";

    let _output = Command::new(cmd)
        .arg(file)
        .output()
        .expect("N1CTF ERROR: failed to run command!");
}



#[tokio::main]
async fn main() {

    log4rs::init_file("log4rs.yaml", Default::default()).unwrap();

    // 定义 submit 接口的过滤器
    let submit = warp::path!("n1ctf" / "submit")
        .and(warp::query::<SubmitParams>())
        .and(warp::path::full())
        .and(
            // Optional query string. See https://github.com/seanmonstar/warp/issues/86
            warp::filters::query::raw()
                .or(warp::any().map(|| String::default()))
                .unify()
        )
        .map(|params: SubmitParams, p: FullPath, query_params: String| {

            info!("[*] [INFO] N1CTF received submit request: {}?{}", p.as_str(), query_params);

            let t = get_timestamp().to_string();
            let taskid: String = get_task_key(&params.urlscheme);
            let task = N1CTFTask {
                task_id: (&taskid).to_string(),
                payload: params.urlscheme.to_string(),
                timestamp: t,
                status: "0".to_string(),
            };
            let redis_payload = serde_json::to_string(&task).unwrap();
            let redis = RedisConnection::connect("redis://127.0.0.1:6379".to_string()).unwrap();
            let result = RedisConnection::push_task(&redis, &redis_payload);
            
            match result {
                Ok(_) => {
                    return warp::reply::with_status(
                        format!(
                            "[*] N1CTF Submit API: Received team={} and urlscheme={}. Your taskid is {}!",
                            params.team, params.urlscheme, taskid,
                        ),
                        warp::http::StatusCode::OK,
                    );
                }
                Err(_e) => {

                    error!("[*] [ERROR] N1CTF insert redis error, request: {}?{}", p.as_str(), query_params);

                    return warp::reply::with_status(
                        format!("[*] N1CTF ERROR: redis insert error: {}", 
                            _e.to_string()
                        ),
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    );
                }
            }
        });

    // 定义 query 接口的过滤器
    let query = warp::path!("n1ctf" / "query")
        .and(warp::query::<QueryParams>())
        .map(|params: QueryParams| {

            let redis = RedisConnection::connect("redis://127.0.0.1:6379".to_string()).unwrap();
            let result = RedisConnection::query_task(&redis, &params.taskid);
            match result {
                Ok(_) => {
                    return warp::reply::with_status(
                        format!(
                            "[*] N1CTF SCUESS: The task {} you submitted has been completed!",
                            params.taskid
                        ),
                        warp::http::StatusCode::OK,
                    );
                }
                Err(_) => {
                    return warp::reply::with_status(
                        format!(
                            "[*] N1CTF ERROR: The task is still in the queue, please check later!"
                        ),
                        warp::http::StatusCode::OK,
                    );
                }
            }
        });


    thread::spawn(run);

    // 合并两个接口的过滤器
    let api = submit.or(query);
    // 启动HTTP服务器
    warp::serve(api)
        .run(([0, 0, 0, 0], 1024))
        .await;
}
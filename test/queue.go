package main

import (
	"fmt"
	"time"
	"runtime"
)

const (
	MaxJobs = 100
	MaxWorkers = 10
)



type JobQueue struct {
	Jobs chan Job
}

func NewJobQueue(maxJobs int) *JobQueue {
	return &JobQueue{
		Jobs: make(chan Job, maxJobs),
	}
}

func (j *JobQueue) Length() int {
	return len(j.Jobs)
}

func (j *JobQueue) Add(job Job) {
	j.Jobs <-job
}

type Job struct {
	Id int
}

type Worker struct {
	Id 		int
	Pool 	chan chan Job
	JobChan chan Job
	Quit 	chan bool
}

func NewWorker(id int, pool chan chan Job) Worker {
	fmt.Printf("创建工作者: ID: %d, Pool: %+v\n", id, pool)
	return Worker{
		Id:		 id,
		Pool:  	 pool,
		JobChan: make(chan Job),
		Quit: 	 make(chan bool),
	}
}

func (w Worker) Start() {
	go func() {
		for {
			// 加入空闲池
			w.Pool <-w.JobChan
			//fmt.Printf("JobChan(%v)->Pool(%v)\n", w.JobChan, w.Pool)
			select {
			case job := <-w.JobChan:
				fmt.Printf("工作者(%d)收到任务(%+v)\n", w.Id, job)
				fmt.Println("可用工人数:", len(w.Pool))
				time.Sleep(10*time.Second)
				fmt.Printf("工作者(%d)完成任务(%+v)\n", w.Id, job)
			case <-w.Quit:
				return
			}
		}
	}()
}

func (w Worker) Stop() {
	go func() {
		w.Quit <- true
	}()
}

type Dispatcher struct {
	Workers 	int
	JobQueue	*JobQueue
	WorkerPool 	chan chan Job
}

func NewDispatcher(worker int, queue *JobQueue) *Dispatcher {
	pool := make(chan chan Job, worker)
	return &Dispatcher{
		WorkerPool:	pool,
		Workers: 	worker,
		JobQueue:	queue,
	}
}

func (d *Dispatcher) Run() {
	for i:=0; i < d.Workers; i++ {
		worker := NewWorker(i, d.WorkerPool)
		worker.Start()
	}
	go d.Dispatch()
}

//func (d *Dispatcher) Dispatch() {
//	for {
//		fmt.Printf("任务个数: %d\n", len(JobQueue))
//		select {
//		case job := <-JobQueue:
//			fmt.Printf("分派任务: %+v\n", job)
//			go func(job Job) {
//				worker := <-d.WorkerPool
//				fmt.Printf("空闲工作者: %+v\n", worker)
//				worker <- job
//				fmt.Printf("分派任务(%+v)给空闲工作者(%+v)\n", job, worker)
//			}(job)
//		}
//	}
//}

func (d *Dispatcher) Dispatch() {
	for {
		if len(d.WorkerPool) > 0 {
			select {
			case job := <-d.JobQueue.Jobs:
				fmt.Printf("分派任务: %+v\n", job)
				go func(job Job) {
					worker := <-d.WorkerPool
					fmt.Printf("空闲工作者: %+v\n", worker)
					worker <- job
					fmt.Printf("分派任务(%+v)给空闲工作者(%+v)\n", job, worker)
				}(job)
			}
		}
	}
}

func main() {
	jobs := NewJobQueue(MaxJobs)
	d := NewDispatcher(MaxWorkers, jobs)
	d.Run()
	for i := 1; i< 20; i++ {
		job := Job{Id: i}
		fmt.Println("======================")
		fmt.Printf("新的任务: %d\n", job)
		jobs.Add(job)
		fmt.Println("添加任务到队列: 成功")
		fmt.Printf("队列状况: %d/%d\n", jobs.Length(), MaxJobs)
		fmt.Println("协程数:", runtime.NumGoroutine())
		time.Sleep(100*time.Millisecond)
	}

	//
	time.Sleep(10*time.Hour)
}
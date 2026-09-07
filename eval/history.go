package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/whiteclover0542/secrethound/internal/finding"
	"github.com/whiteclover0542/secrethound/internal/scanner"
	"gopkg.in/yaml.v3"
)

type historySpec struct {
	Version  int             `yaml:"version"`
	Commits  []historyCommit `yaml:"commits"`
	History  []historyExpect `yaml:"history_expected"`
	Worktree []historyExpect `yaml:"worktree_expected"`
}

type historyCommit struct {
	Message string        `yaml:"message"`
	Write   []historyFile `yaml:"write"`
	Delete  []string      `yaml:"delete"`
}

type historyFile struct {
	Path    string `yaml:"path"`
	Content string `yaml:"content"`
}

type historyExpect struct {
	Path string `yaml:"path"`
	Line int    `yaml:"line"`
	Kind string `yaml:"kind"`
	Note string `yaml:"note"`
}

// runHistoryEval은 시나리오대로 임시 git 레포를 만들어
// 워킹트리 스캔과 히스토리 스캔을 각각 채점한다.
func runHistoryEval(specPath, rulesPath string) error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git이 설치되어 있지 않아 히스토리 평가를 실행할 수 없습니다")
	}

	data, err := os.ReadFile(specPath)
	if err != nil {
		return err
	}
	var spec historySpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return fmt.Errorf("시나리오 파싱 실패: %w", err)
	}

	repo, err := os.MkdirTemp("", "secrethound-history-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(repo)

	if err := buildRepo(repo, spec.Commits); err != nil {
		return err
	}

	rs, err := loadRuleset(rulesPath)
	if err != nil {
		return err
	}

	worktree, err := scanner.Run(context.Background(), rs, scanner.Options{Target: repo})
	if err != nil {
		return fmt.Errorf("워킹트리 스캔 실패: %w", err)
	}
	withHistory, err := scanner.Run(context.Background(), rs, scanner.Options{Target: repo, History: true})
	if err != nil {
		return fmt.Errorf("히스토리 스캔 실패: %w", err)
	}

	fmt.Printf("시나리오: 커밋 %d개\n\n", len(spec.Commits))

	ok := report("워킹트리 스캔 (--history 없음)", spec.Worktree, toLocationSet(worktree.Findings))
	fmt.Println()
	ok = report("히스토리 스캔 (--history)", spec.History, toLocationSet(withHistory.Findings)) && ok

	if !ok {
		return fmt.Errorf("히스토리 평가 실패")
	}
	fmt.Println("\n모든 기대 결과가 일치합니다.")
	return nil
}

func buildRepo(repo string, commits []historyCommit) error {
	init := [][]string{
		{"init", "-q"},
		{"config", "user.email", "eval@example.com"},
		{"config", "user.name", "eval"},
	}
	for _, args := range init {
		if err := runGit(repo, args...); err != nil {
			return err
		}
	}

	for i, c := range commits {
		for _, f := range c.Write {
			path := filepath.Join(repo, filepath.FromSlash(f.Path))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(path, []byte(f.Content), 0o644); err != nil {
				return err
			}
		}
		for _, p := range c.Delete {
			if err := os.Remove(filepath.Join(repo, filepath.FromSlash(p))); err != nil {
				return err
			}
		}

		if err := runGit(repo, "add", "-A"); err != nil {
			return err
		}
		msg := c.Message
		if msg == "" {
			msg = fmt.Sprintf("commit %d", i+1)
		}
		if err := runGit(repo, "commit", "-q", "-m", msg); err != nil {
			return err
		}
	}
	return nil
}

func runGit(repo string, args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git %s 실패: %w\n%s", strings.Join(args, " "), err, out)
	}
	return nil
}

func toLocationSet(findings []finding.Finding) map[location]prediction {
	set := make(map[location]prediction, len(findings))
	for _, f := range findings {
		set[location{filepath.ToSlash(f.Path), f.Line}] = prediction{
			RuleID:   f.RuleID,
			Severity: string(f.Severity),
		}
	}
	return set
}

func report(title string, expected []historyExpect, got map[location]prediction) bool {
	fmt.Printf("%s\n", title)

	ok := true
	seen := make(map[location]bool, len(expected))

	for _, e := range expected {
		loc := location{e.Path, e.Line}
		seen[loc] = true

		p, found := got[loc]
		switch {
		case !found:
			fmt.Printf("  [미탐] %s:%d  %s\n", e.Path, e.Line, e.Note)
			ok = false
		case e.Kind != "" && e.Kind != p.RuleID:
			fmt.Printf("  [오분류] %s:%d  기대 %s → 실제 %s\n", e.Path, e.Line, e.Kind, p.RuleID)
			ok = false
		default:
			fmt.Printf("  [정상] %s:%d  %s  (%s)\n", e.Path, e.Line, p.RuleID, e.Note)
		}
	}

	for loc, p := range got {
		if !seen[loc] {
			fmt.Printf("  [오탐] %s:%d  %s\n", loc.Path, loc.Line, p.RuleID)
			ok = false
		}
	}

	return ok
}

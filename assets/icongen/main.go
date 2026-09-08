// secrethound 아이콘 생성기.
//
// 의존성 없이 표준 라이브러리만으로 그린다. 안티에일리어싱은 4배 크기로 그린 뒤
// 축소하는 방식(수퍼샘플링)으로 얻는다.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

const scale = 4 // 수퍼샘플링 배율

var (
	bgDark   = color.NRGBA{0x1B, 0x1F, 0x27, 0xFF} // 배경
	bgEdge   = color.NRGBA{0x2A, 0x30, 0x3C, 0xFF} // 배경 테두리
	accent   = color.NRGBA{0xF5, 0xA6, 0x23, 0xFF} // 돋보기 테=열쇠
	accentHi = color.NRGBA{0xFF, 0xC7, 0x5B, 0xFF} // 하이라이트
	hole     = color.NRGBA{0x12, 0x15, 0x1B, 0xFF} // 열쇠구멍
)

func main() {
	sizes := []int{16, 24, 32, 48, 64, 128, 256}

	outDir := "."
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}

	var pngs [][]byte
	for _, s := range sizes {
		img := render(s)

		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			panic(err)
		}
		pngs = append(pngs, buf.Bytes())

		// 미리보기용 PNG도 남긴다.
		if s == 256 || s == 64 || s == 32 || s == 16 {
			name := filepath.Join(outDir, fmt.Sprintf("preview-%d.png", s))
			if err := os.WriteFile(name, buf.Bytes(), 0o644); err != nil {
				panic(err)
			}
		}
	}

	ico, err := buildICO(sizes, pngs)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "icon.ico"), ico, 0o644); err != nil {
		panic(err)
	}
	fmt.Println("wrote", filepath.Join(outDir, "icon.ico"), len(ico), "bytes")
}

// render는 한 변이 size 픽셀인 아이콘을 그린다.
func render(size int) *image.NRGBA {
	n := size * scale
	big := image.NewNRGBA(image.Rect(0, 0, n, n))

	f := float64(n)
	radius := f * 0.22 // 둥근 모서리

	// 배경: 둥근 사각형
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			if insideRoundRect(float64(x)+0.5, float64(y)+0.5, f, f, radius) {
				big.SetNRGBA(x, y, bgDark)
			}
		}
	}
	// 배경 테두리(살짝 밝게) — 어두운 테마에서 아이콘 경계가 사라지지 않게 한다.
	strokeRoundRect(big, f, radius, f*0.02, bgEdge)

	cx, cy := f*0.44, f*0.42 // 돋보기 렌즈 중심
	lens := f * 0.26         // 렌즈 반지름
	ring := f * 0.085        // 테 두께

	// 손잡이: 렌즈 오른쪽 아래로 뻗는 굵은 선
	hx1, hy1 := cx+lens*0.72, cy+lens*0.72
	hx2, hy2 := f*0.84, f*0.84
	drawLine(big, hx1, hy1, hx2, hy2, ring*1.05, accent)

	// 렌즈 테
	drawRing(big, cx, cy, lens, ring, accent)

	// 렌즈 안쪽: 열쇠구멍 (원 + 아래로 벌어지는 목)
	kr := lens * 0.34
	drawDisc(big, cx, cy-lens*0.12, kr, hole)
	drawTaperedStem(big, cx, cy-lens*0.12+kr*0.6, kr*0.62, kr*0.22, lens*0.72, hole)

	// 테 왼쪽 위에 하이라이트 한 줄
	drawArc(big, cx, cy, lens, ring*0.38, math.Pi*1.05, math.Pi*1.45, accentHi)

	return downsample(big, size)
}

func insideRoundRect(x, y, w, h, r float64) bool {
	if x < 0 || y < 0 || x > w || y > h {
		return false
	}
	// 각 모서리 안쪽 원의 중심까지 거리로 판정한다.
	switch {
	case x < r && y < r:
		return math.Hypot(x-r, y-r) <= r
	case x > w-r && y < r:
		return math.Hypot(x-(w-r), y-r) <= r
	case x < r && y > h-r:
		return math.Hypot(x-r, y-(h-r)) <= r
	case x > w-r && y > h-r:
		return math.Hypot(x-(w-r), y-(h-r)) <= r
	}
	return true
}

func strokeRoundRect(img *image.NRGBA, f, r, thick float64, c color.NRGBA) {
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			px, py := float64(x)+0.5, float64(y)+0.5
			in := insideRoundRect(px, py, f, f, r)
			inner := insideRoundRect(px, py, f, f, r) &&
				insideRoundRectShrunk(px, py, f, r, thick)
			if in && !inner {
				img.SetNRGBA(x, y, c)
			}
		}
	}
}

func insideRoundRectShrunk(x, y, f, r, d float64) bool {
	return insideRoundRect(x-d, y-d, f-2*d, f-2*d, math.Max(r-d, 0))
}

func drawDisc(img *image.NRGBA, cx, cy, r float64, c color.NRGBA) {
	forBox(img, cx, cy, r, func(x, y int, px, py float64) {
		if math.Hypot(px-cx, py-cy) <= r {
			img.SetNRGBA(x, y, c)
		}
	})
}

func drawRing(img *image.NRGBA, cx, cy, r, thick float64, c color.NRGBA) {
	forBox(img, cx, cy, r+thick, func(x, y int, px, py float64) {
		d := math.Hypot(px-cx, py-cy)
		if d <= r && d >= r-thick {
			img.SetNRGBA(x, y, c)
		}
	})
}

func drawArc(img *image.NRGBA, cx, cy, r, thick, from, to float64, c color.NRGBA) {
	forBox(img, cx, cy, r+thick, func(x, y int, px, py float64) {
		d := math.Hypot(px-cx, py-cy)
		if d > r || d < r-thick {
			return
		}
		a := math.Atan2(py-cy, px-cx)
		if a < 0 {
			a += 2 * math.Pi
		}
		if a >= from && a <= to {
			img.SetNRGBA(x, y, c)
		}
	})
}

// drawLine은 끝이 둥근 굵은 선을 그린다.
func drawLine(img *image.NRGBA, x1, y1, x2, y2, thick float64, c color.NRGBA) {
	minX := int(math.Floor(math.Min(x1, x2) - thick - 1))
	maxX := int(math.Ceil(math.Max(x1, x2) + thick + 1))
	minY := int(math.Floor(math.Min(y1, y2) - thick - 1))
	maxY := int(math.Ceil(math.Max(y1, y2) + thick + 1))

	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			if !image.Pt(x, y).In(img.Bounds()) {
				continue
			}
			if distToSegment(float64(x)+0.5, float64(y)+0.5, x1, y1, x2, y2) <= thick/2 {
				img.SetNRGBA(x, y, c)
			}
		}
	}
}

// drawTaperedStem은 위가 넓고 아래가 좁아지는 열쇠구멍의 목을 그린다.
func drawTaperedStem(img *image.NRGBA, cx, top, wTop, wBot, h float64, c color.NRGBA) {
	for y := int(top); y <= int(top+h); y++ {
		fy := float64(y) + 0.5
		if fy < top || fy > top+h {
			continue
		}
		t := (fy - top) / h
		w := wTop + (wBot-wTop)*t
		for x := int(cx - w); x <= int(cx+w); x++ {
			if !image.Pt(x, y).In(img.Bounds()) {
				continue
			}
			if math.Abs(float64(x)+0.5-cx) <= w {
				img.SetNRGBA(x, y, c)
			}
		}
	}
}

func forBox(img *image.NRGBA, cx, cy, r float64, fn func(x, y int, px, py float64)) {
	minX, maxX := int(cx-r-1), int(cx+r+1)
	minY, maxY := int(cy-r-1), int(cy+r+1)

	for y := minY; y <= maxY; y++ {
		for x := minX; x <= maxX; x++ {
			if !image.Pt(x, y).In(img.Bounds()) {
				continue
			}
			fn(x, y, float64(x)+0.5, float64(y)+0.5)
		}
	}
}

func distToSegment(px, py, x1, y1, x2, y2 float64) float64 {
	dx, dy := x2-x1, y2-y1
	l2 := dx*dx + dy*dy
	if l2 == 0 {
		return math.Hypot(px-x1, py-y1)
	}
	t := ((px-x1)*dx + (py-y1)*dy) / l2
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(x1+t*dx), py-(y1+t*dy))
}

// downsample은 scale배로 그린 이미지를 목표 크기로 평균내어 줄인다.
func downsample(src *image.NRGBA, size int) *image.NRGBA {
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a int
			for sy := 0; sy < scale; sy++ {
				for sx := 0; sx < scale; sx++ {
					c := src.NRGBAAt(x*scale+sx, y*scale+sy)
					// 알파를 곱해 더해야 투명한 배경색이 가장자리로 번지지 않는다.
					r += int(c.R) * int(c.A) / 255
					g += int(c.G) * int(c.A) / 255
					b += int(c.B) * int(c.A) / 255
					a += int(c.A)
				}
			}
			n := scale * scale
			if a == 0 {
				dst.SetNRGBA(x, y, color.NRGBA{})
				continue
			}
			// 곱해둔 알파를 되돌린다.
			aa := a / n
			dst.SetNRGBA(x, y, color.NRGBA{
				R: uint8(clamp(r * 255 / a)),
				G: uint8(clamp(g * 255 / a)),
				B: uint8(clamp(b * 255 / a)),
				A: uint8(clamp(aa)),
			})
		}
	}
	return dst
}

func clamp(v int) int {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return v
}

// buildICO는 PNG를 그대로 담는 ICO 컨테이너를 만든다.
// Windows Vista 이상은 ICO 안의 PNG 데이터를 그대로 읽는다.
func buildICO(sizes []int, pngs [][]byte) ([]byte, error) {
	if len(sizes) != len(pngs) {
		return nil, fmt.Errorf("크기와 이미지 개수가 다릅니다")
	}

	var buf bytes.Buffer

	// ICONDIR: reserved(0), type(1=icon), count
	binary.Write(&buf, binary.LittleEndian, uint16(0))
	binary.Write(&buf, binary.LittleEndian, uint16(1))
	binary.Write(&buf, binary.LittleEndian, uint16(len(sizes)))

	offset := 6 + 16*len(sizes)
	for i, s := range sizes {
		// 256은 0으로 표기한다 (1바이트 필드라 256을 담을 수 없다).
		dim := byte(s)
		if s >= 256 {
			dim = 0
		}
		buf.WriteByte(dim)                                            // width
		buf.WriteByte(dim)                                            // height
		buf.WriteByte(0)                                              // 팔레트 색 수 (PNG는 0)
		buf.WriteByte(0)                                              // reserved
		binary.Write(&buf, binary.LittleEndian, uint16(1))            // 색상 평면
		binary.Write(&buf, binary.LittleEndian, uint16(32))           // 비트 깊이
		binary.Write(&buf, binary.LittleEndian, uint32(len(pngs[i]))) // 데이터 크기
		binary.Write(&buf, binary.LittleEndian, uint32(offset))       // 데이터 위치
		offset += len(pngs[i])
	}
	for _, p := range pngs {
		buf.Write(p)
	}
	return buf.Bytes(), nil
}

import { useId, type SVGProps } from 'react'

type GeistIconProps = SVGProps<SVGSVGElement>

export function Bell({ width = 16, height = 16, ...props }: GeistIconProps) {
  const clipId = useId()
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={width} height={height} fill="none" viewBox="0 0 16 16" {...props}>
      <g clipPath={`url(#${clipId})`}>
        <path
          fill="currentColor"
          fillRule="evenodd"
          d="M7.992 0a5.507 5.507 0 0 0-5.507 5.508v2.719c0 .546-.272 1.057-.725 1.362l-.429.289L1 10.1V12h14v-1.901l-.334-.223-.435-.29A1.64 1.64 0 0 1 13.5 8.22V5.508A5.51 5.51 0 0 0 7.992 0M3.986 5.508a4.008 4.008 0 0 1 8.015 0V8.22c0 .87.36 1.691.98 2.279H3.012a3.14 3.14 0 0 0 .973-2.273v-2.72zM10.75 13.5H9.168l-.005.013a1.03 1.03 0 0 1-.442.537 1.36 1.36 0 0 1-.721.2 1.36 1.36 0 0 1-.72-.2 1.03 1.03 0 0 1-.443-.537l-.005-.013h-1.58l.161.487c.188.565.58 1.028 1.072 1.336.437.272.96.427 1.515.427a2.86 2.86 0 0 0 1.515-.427c.502-.307.881-.78 1.072-1.336z"
          clipRule="evenodd"
        />
      </g>
      <defs>
        <clipPath id={clipId}>
          <path fill="currentColor" d="M0 0h16v16H0z" />
        </clipPath>
      </defs>
    </svg>
  )
}

export function Sun({ width = 16, height = 16, ...props }: GeistIconProps) {
  const clipId = useId()
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={width} height={height} fill="none" viewBox="0 0 16 16" {...props}>
      <g clipPath={`url(#${clipId})`}>
        <path
          fill="currentColor"
          fillRule="evenodd"
          d="M8.75.75V0h-1.5v2.75h1.5zm2.432 3.007.53-.53.354-.354.53-.53 1.06 1.06-.53.531-.353.354-.53.53zM8 10.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5M8 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8m5.25-4.75H16v1.5h-2.75zm-12.5 0H0v1.5h2.75v-1.5zm2.123 4.816-.53.53 1.06 1.06.531-.53.354-.353.53-.53-1.06-1.061-.531.53zm.884-7.248-.53-.53-.354-.354-.53-.53 1.06-1.06.531.53.354.353.53.53zm8.309 8.309.53.53 1.06-1.06-.53-.531-.353-.354-.53-.53-1.061 1.06.53.531zm-3.316.123V16h-1.5v-2.75z"
          clipRule="evenodd"
        />
      </g>
      <defs>
        <clipPath id={clipId}>
          <path fill="currentColor" d="M0 0h16v16H0z" />
        </clipPath>
      </defs>
    </svg>
  )
}

export function Moon({ width = 16, height = 16, ...props }: GeistIconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={width} height={height} fill="none" viewBox="0 0 16 16" {...props}>
      <path
        fill="currentColor"
        fillRule="evenodd"
        d="M1.5 8c0-2.47 1.492-4.59 3.623-5.511a7 7 0 0 0 7.072 9.247A6 6 0 0 1 1.5 8M6.417.578A7.502 7.502 0 0 0 7.5 15.5a7.5 7.5 0 0 0 6.88-4.508l-.921-1.012A5.5 5.5 0 0 1 7.15 1.732zM13.25 1v1.75H15v1.5h-1.75V6h-1.5V4.25H10v-1.5h1.75V1z"
        clipRule="evenodd"
      />
    </svg>
  )
}

export function ChevronRight({ width = 16, height = 16, ...props }: GeistIconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={width} height={height} fill="none" viewBox="0 0 16 16" {...props}>
      <path
        fill="currentColor"
        fillRule="evenodd"
        d="m5.5 1.94.53.53 4.824 4.823a1 1 0 0 1 0 1.414L6.03 13.53l-.53.53L4.44 13l.53-.53L9.44 8 4.97 3.53 4.44 3z"
        clipRule="evenodd"
      />
    </svg>
  )
}

export function ArrowLeft({ width = 16, height = 16, ...props }: GeistIconProps) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width={width} height={height} fill="none" viewBox="0 0 16 16" {...props}>
      <path
        fill="currentColor"
        fillRule="evenodd"
        d="m6.47 13.78.53.53 1.06-1.06-.53-.53-3.97-3.97H15v-1.5H3.56l3.97-3.97.53-.53L7 1.69l-.53.53-5.074 5.073a1 1 0 0 0 0 1.414z"
        clipRule="evenodd"
      />
    </svg>
  )
}
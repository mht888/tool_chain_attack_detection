import Dashboard from '../views/Dashboard'
import Detect from '../views/Detect'
import ReportList from '../views/ReportList'
import ReportDetail from '../views/ReportDetail'

export default [
  {
    path: '/',
    element: <Dashboard />,
  },
  {
    path: '/detect',
    element: <Detect />,
  },
  {
    path: '/reports',
    element: <ReportList />,
  },
  {
    path: '/reports/:reportId',
    element: <ReportDetail />,
  },
]
